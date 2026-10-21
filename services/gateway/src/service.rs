//! The enforcement service: the gateway's brain, independent of transport.
//!
//! Both the REST endpoints and the MCP JSON-RPC surface call into this module so the
//! enforcement loop is defined exactly once:
//!
//! 1. identify the agent/session from a bearer token,
//! 2. load the grants for the capability's resource,
//! 3. run [`permaura_policy::PolicyEngine`] to a [`Decision`],
//! 4. on Deny → return the reason; on RequiresApproval → record a pending approval;
//!    on Allow → resolve the sealed secret, run the connector through the HTTP client, command
//!    runner or SSH runner the service was built with (real transports in a shipped gateway, mocks
//!    in the demo and tests), redact the result, and append a hash-chained audit event,
//! 5. scrub the injected credential out of everything returned (by value for credentials of 8 bytes
//!    or more, in the encodings [`CredentialScrub`] covers, and by key name always).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use permaura_core::{
    seal, AuditPayload, Cipher, CredentialScrub, Decision, DecisionKind, ExecutionLocation, JsonText,
    OpenedSecret, Principal, Rung, SealedSecret,
};
use permaura_policy::{DecisionInput, PolicyEngine, RequestContext};
use permaura_relay::{
    approval_result_preimage, approval_result_preimage_v2, approval_result_preimage_v3, verify as verify_sig,
    ApprovalResult,
};
use time::OffsetDateTime;

use crate::backend::{Lease, LocalVaultBackend, SecretBackend};
use crate::connectors::json_budget::MemoryCharge;
use crate::connectors::{
    self, Capability, CapabilityKind, CommandRunner, HttpClient, MockSshRunner, SshOutcome,
    SshRunner,
};
use crate::error::GatewayError;
use crate::policy_guard::{MutationNames, Stored};
use crate::relay::approver::ApproverKeyring;
use crate::store::{
    Agent, AgentStatus, PendingApproval, Session, SessionRole, Store, APPROVAL_AUDIENCE_META,
    APPROVAL_FLOOR_ADOPTED_META, APPROVAL_FLOOR_META, APPROVAL_FLOOR_UNANCHORED_META, APPROVAL_UNRESOLVED, HELD_EFFECT_META_PREFIX,
    APPROVER_KEYRING_META,
    BROKER_PAUSED_META, BROKER_REQUIRE_AGENT_APPROVAL_META, BROKER_REQUIRE_AGENT_APPROVAL_UNANCHORED_META,
    DEVICE_SIG_DISPLAY_APPROVERS_META,
    DEVICE_SIG_V2_APPROVERS_META, QUORUM_HIGH_WATER_META,
};

/// Refresh an OAuth access token this far before it actually expires, so a call never races the
/// expiry: the token has to survive the upstream request it is about to be used for.
const OAUTH_REFRESH_SKEW_MS: i64 = 120_000;

/// The offline/dev KEK passphrase. Public in source, so it provides NO confidentiality; it exists
/// only so the envelope encryption runs end-to-end without a key-management dependency in dev/test.
pub(crate) const DEV_VAULT_PASSPHRASE: &[u8] = b"permaura-dev-vault-passphrase";

static VAULT_KEK: OnceLock<Vec<u8>> = OnceLock::new();

/// Which hand-over route the environment is asking for.
///
/// Split out from the readers so the ORDER, the part that decides whether a deployment keeps handing
/// the key over in the clear, is testable without a pipe, a file or a process environment.
#[derive(Debug, PartialEq, Eq)]
enum Handover {
    /// Read it from stdin. Nothing at rest.
    Stdin,
    /// Read it from this path. What a secret manager mounts.
    File(String),
    /// The inline variable was set. Its value is NOT carried: it is read only so the boot can say
    /// the variable is being ignored, because a deployment that still sets it would otherwise get a
    /// silent fall-through to a different key.
    Ignored,
    /// Nothing was handed over; fall through to the per-install key or the refusal.
    None,
}

/// Pick the route. Safest first, and an EMPTY value is not a hand-over: a caller that sets the path
/// to "" means a broken mount, not an offer.
fn handover_from(stdin: bool, file: Option<String>, inline: Option<String>) -> Handover {
    if stdin {
        return Handover::Stdin;
    }
    if let Some(path) = file.filter(|p| !p.is_empty()) {
        return Handover::File(path);
    }
    if inline.is_some_and(|p| !p.is_empty()) {
        return Handover::Ignored;
    }
    Handover::None
}

/// An env flag that means yes.
pub(crate) fn truthy_env(key: &str) -> bool {
    std::env::var(key).map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Strip the trailing newline a file or a pipe write usually carries, and reject an empty result.
///
/// `None` rather than an empty vec on purpose: an empty KEK is not a KEK, and returning one would seal
/// a whole vault under nothing while looking like a success.
fn trim_trailing_newlines(mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    let end = bytes.iter().rposition(|b| *b != b'\n' && *b != b'\r').map(|i| i + 1)?;
    // In place: the key is not copied, so no second copy of it is freed unwiped.
    bytes.truncate(end);
    Some(bytes)
}

/// Read the KEK from stdin, which the parent writes and then closes.
///
/// The point of this route is that the secret is never at rest anywhere a second process can look: not
/// in the environment block, not in a file. It exists in the pipe until this read drains it.
///
/// Refused when stdin is a terminal. Without that check, a person who set the variable by hand would
/// get a process that hangs on a read waiting for a supervisor that is never going to write, and would
/// have no way to tell that apart from a gateway that is simply slow to start.
fn read_kek_from_stdin() -> Result<Vec<u8>, String> {
    use std::io::{IsTerminal, Read};
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err("PERMAURA_VAULT_PASSPHRASE_STDIN is set but stdin is a terminal, so there is no \
                    supervisor to read it from. It is meant to be set by a parent process that writes \
                    the key and closes the pipe."
            .to_string());
    }
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf).map_err(|e| format!("reading stdin failed: {e}"))?;
    trim_trailing_newlines(buf).ok_or_else(|| "stdin closed without a key".to_string())
}

/// The KEK passphrase that seals every connector credential at rest. Resolution order:
/// 1. `PERMAURA_VAULT_PASSPHRASE_STDIN=1`: read it from stdin, which the parent writes and closes.
///    The only route that leaves no readable copy anywhere: not in the environment block, not on
///    disk. This is how the desktop supervisor hands over the KEK it holds in the OS credential
///    store. Refused when stdin is a terminal, because a human typing this by hand would otherwise
///    hang forever on a read that is waiting for a supervisor that does not exist.
/// 2. `PERMAURA_VAULT_PASSPHRASE_FILE`: read the passphrase from a file (trailing newline trimmed).
///    A path is what a secret manager mounts: Cloud Run, Kubernetes and systemd credentials all
///    deliver secrets this way, and the file is not visible to a process that merely shares the uid.
///    A route from 1-2 that is set and delivers nothing (a pipe closed empty, a missing or empty
///    file) refuses to start rather than falling through: see [`handed_over`].
/// 3. The gateway's OWN per-install KEK, resolved through `permaura-credential-store` from the best
///    custody this machine offers: the OS credential store where one is usable, an owner-only
///    `~/.permaura/vault-kek` where it is not, generated on genuine first run. This is what makes
///    routes 1-2 optional rather than load-bearing: in earlier builds the desktop app held this key and had
///    to hand it over, and whoever started the gateway decided which key it got. Skipped when
///    `PERMAURA_HOSTED=1`, where the FS is ephemeral and the KEK must arrive from a durable store via
///    1-2. A refusal here is fatal and never falls through to step 4, and a fresh key is never minted
///    while the store holds credentials sealed under a real one.
/// 4. The dev constant: silently under test, and with `PERMAURA_DEV=1` in a debug build that is not
///    hosted, logged at error level. A release or hosted process ignores the variable. Anywhere else this is a REFUSAL,
///    not a fallback: a gateway that cannot obtain a real KEK will not start. Sealing under a constant
///    that is published in an open-source repository is not encryption, and the loud warning that used
///    to stand in for this was a line in a log nobody reads on a process that came up healthy and then
///    accepted real credentials. `PERMAURA_ALLOW_INSECURE_VAULT=1` opts back out, for the one case that
///    justifies it (poking at a throwaway install) and says so on every boot.
///    Resolved once and cached for the process life.
///
/// `PERMAURA_VAULT_PASSPHRASE` (the inline variable) is GONE, and a boot that finds it set says so
/// and ignores it. An environment block is readable by anything running as the same user (`ps eww
/// <pid>` on macOS, `/proc/<pid>/environ` on Linux), it is inherited by every child, and it is
/// captured by crash dumps; on a machine whose KEK otherwise lives in the Keychain, which prompts
/// before handing the value to an untrusted binary, putting it there gave away everything that
/// custody buys. Unsetting it after boot never fixed that: `/proc/<pid>/environ` exposes the initial
/// process stack, so a later `remove_var` does not scrub what a reader already sees. The value has to
/// not be placed there at all.
pub fn vault_passphrase() -> &'static [u8] {
    VAULT_KEK
        .get_or_init(|| {
            let route = handover_from(
                truthy_env("PERMAURA_VAULT_PASSPHRASE_STDIN"),
                std::env::var("PERMAURA_VAULT_PASSPHRASE_FILE").ok(),
                std::env::var("PERMAURA_VAULT_PASSPHRASE").ok(),
            );
            match handed_over(&route, read_kek_from_stdin, |path| std::fs::read(path)) {
                Ok(Some(kek)) => return kek,
                Ok(None) => {}
                // NOT a fall-through. Whoever set the route meant this key, and
                // anything resolved in its place is a different one: the per-install key would be
                // minted fresh and the vault sealed under the intended key left unreadable.
                Err(why) => panic!("refusing to start: {why}"),
            }
            match route {
                Handover::Ignored => tracing::warn!(
                    "PERMAURA_VAULT_PASSPHRASE is set and is being IGNORED: the inline hand-over was \
                     removed. Anything running as this user could read it out of the process environment, \
                     every child inherited it, and unsetting it after boot did not scrub what a reader \
                     sees. Hand the KEK over on stdin (PERMAURA_VAULT_PASSPHRASE_STDIN=1) or at a path \
                     (PERMAURA_VAULT_PASSPHRASE_FILE) instead. This gateway is now resolving a DIFFERENT \
                     key, so a vault sealed under the inline value will not open."
                ),
                Handover::Stdin | Handover::File(_) | Handover::None => {}
            }
            // `PERMAURA_SEED=1` used to count as a dev signal here, so one variable meant both "give
            // me fake data" and "don't provision real key custody". Seeding is no longer an env
            // decision at all, and conflating the two is how a gateway could end up looking like a
            // demo to this check while holding a customer's credentials. `PERMAURA_DEV` says it.
            let dev = cfg!(test) || dev_kek_for_this_process();
            // A real (non-dev) gateway that wasn't handed a KEK: resolve a per-install one from
            // whatever custody this machine offers rather than seal under the PUBLIC dev constant.
            // This is the gateway's OWN custody, not something the desktop app lends it.
            // Skipped when hosted: a Cloud Run FS is ephemeral, so a regenerated file would
            // orphan the vault on the next cold start, and hosted injects the KEK
            // from a durable store via steps 1-2.
            if !dev && !truthy_env("PERMAURA_HOSTED") {
                match persistent_install_kek() {
                    Ok(kek) => return kek,
                    // NOT a fall-through. The custody layer only says this when it knows a key was
                    // put somewhere it can no longer read from: a locked keychain, a keyring that
                    // came back empty, a session with no bus. Carrying on would mint a second KEK and
                    // silently orphan every credential sealed under the first, which is the defect
                    // this whole path exists to make impossible. Refuse, and say why.
                    // No hint about the desktop app any more. It used to say "open it once, it hands
                    // the key back", which was true for exactly one release and is now advice that
                    // does nothing: the app never takes custody of this key and has no hand-back to
                    // run. Telling someone to open an app that will not help is worse than saying
                    // nothing, and `why` already carries the recovery path.
                    Err(why) => panic!("refusing to start: {why}"),
                }
            }
            // FAIL CLOSED. Reaching here on a real gateway means every route to a real key failed:
            // nothing injected, no passphrase file, and step 4 could not resolve or persist one (no
            // resolvable home, or a read-only/full disk). The old behaviour was to warn and carry on under
            // `DEV_VAULT_PASSPHRASE` (a constant in a public repository) which produces a gateway
            // that starts, reports itself healthy, accepts a customer's API keys and stores them in a
            // form anyone who can read the file can open. Opting into that is now explicit.
            if !dev {
                if truthy_env("PERMAURA_ALLOW_INSECURE_VAULT") {
                    tracing::error!(
                        "PERMAURA_ALLOW_INSECURE_VAULT is set: sealing secrets under the PUBLIC dev KEK, which gives NO at-rest confidentiality. Anyone who can read this store can decrypt every credential in it. Do not put real credentials in this gateway."
                    );
                } else {
                    panic!("{NO_KEK_REFUSAL}");
                }
            }
            DEV_VAULT_PASSPHRASE.to_vec()
        })
        .as_slice()
}

/// The KEK an explicit hand-over delivered, `None` when none was asked for, or why the one asked for
/// did not arrive.
///
/// A requested route that fails is an error and never `None`, because `None` lets the caller resolve
/// a different key, and on an install whose key lives only in that file or pipe that means minting a
/// fresh one over the live vault. The readers are passed in so every failure is testable without a
/// pipe or a process environment.
fn handed_over(
    route: &Handover,
    read_stdin: impl FnOnce() -> Result<Vec<u8>, String>,
    read_file: impl FnOnce(&str) -> std::io::Result<Vec<u8>>,
) -> Result<Option<Vec<u8>>, String> {
    const DIFFERENT_KEY: &str = "Carrying on would resolve a different key, sealing new credentials under it and leaving every credential sealed under the intended one unreadable";
    match route {
        Handover::Stdin => read_stdin().map(Some).map_err(|e| {
            format!("PERMAURA_VAULT_PASSPHRASE_STDIN is set and no vault KEK arrived on stdin ({e}). {DIFFERENT_KEY}. Start the gateway from the supervisor that hands the key over, or unset the variable.")
        }),
        Handover::File(path) => match read_file(path).map(trim_trailing_newlines) {
            Ok(Some(kek)) => Ok(Some(kek)),
            Ok(None) => Err(format!(
                "PERMAURA_VAULT_PASSPHRASE_FILE names {path}, which is empty. {DIFFERENT_KEY}. Mount the key there, or unset the variable."
            )),
            Err(e) => Err(format!(
                "PERMAURA_VAULT_PASSPHRASE_FILE names {path}, which could not be read ({e}). {DIFFERENT_KEY}. Mount the key there, or unset the variable."
            )),
        },
        Handover::Ignored | Handover::None => Ok(None),
    }
}

/// What `PERMAURA_DEV` does to this process's vault KEK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevKek {
    /// Not set.
    NotRequested,
    /// Set and honored: credentials are sealed under the public dev constant.
    Honored,
    /// Set and ignored, because this is a release build.
    IgnoredInRelease,
    /// Set and ignored, because this is a hosted worker.
    IgnoredWhenHosted,
}

fn dev_kek(requested: bool, debug_build: bool, hosted: bool) -> DevKek {
    match (requested, debug_build, hosted) {
        (false, _, _) => DevKek::NotRequested,
        (true, _, true) => DevKek::IgnoredWhenHosted,
        (true, false, false) => DevKek::IgnoredInRelease,
        (true, true, false) => DevKek::Honored,
    }
}

/// [`dev_kek`] for this process, saying at error level whatever it decided about a set `PERMAURA_DEV`.
fn dev_kek_for_this_process() -> bool {
    match dev_kek(truthy_env("PERMAURA_DEV"), cfg!(debug_assertions), truthy_env("PERMAURA_HOSTED")) {
        DevKek::NotRequested => false,
        DevKek::Honored => {
            tracing::error!(
                "PERMAURA_DEV is set: sealing secrets under the PUBLIC dev KEK, which gives NO at-rest confidentiality. This is a debug build for development; do not put real credentials in it."
            );
            true
        }
        DevKek::IgnoredInRelease => {
            tracing::error!(
                "PERMAURA_DEV is set and IGNORED: a release build never seals under the public dev KEK. Unset it; this gateway resolves its real key."
            );
            false
        }
        DevKek::IgnoredWhenHosted => {
            tracing::error!(
                "PERMAURA_DEV is set on a hosted gateway and IGNORED: a hosted worker never seals under the public dev KEK. Unset it; this gateway resolves its real key or refuses to start."
            );
            false
        }
    }
}

/// Where this gateway's vault KEK lives, in whatever custody the machine offers.
///
/// The service/account/file names are stable forever and are the ones the DESKTOP APP used while it
/// was the holder: `com.permaura.desktop` reads oddly now, but renaming it orphans the KEK of every
/// install that adopted under the old name, which is the exact failure this whole area exists to
/// prevent. `vault-kek` is also the file name every pre-native install already has under the Permaura
/// home, so those are adopted rather than re-minted.
///
/// `needs_stable_code_identity` is set because a gateway is a background service: it gets started by
/// launchd, by systemd, over SSH, by the desktop supervisor, and none of those can answer a macOS
/// Keychain authorization dialog. Until the release pipeline signs the published binary with a
/// Developer ID, that keeps the KEK in the owner-only file on macOS rather than in a keychain item
/// this binary would stop being able to read the next time it updated itself.
pub const VAULT_KEK_CUSTODY: permaura_credential_store::CredentialStore =
    permaura_credential_store::CredentialStore {
        service: "com.permaura.desktop",
        account: "vault-kek",
        file_name: "vault-kek",
        needs_stable_code_identity: true,
        // A server's operator sets `vault_custody = "file"` in config.toml or the environment, and a released gateway must honor it.
        operator_sets_custody: true,
        keychain_access_group: None,
    };

const _: () = assert!(
    VAULT_KEK_CUSTODY.operator_sets_custody,
    "a released gateway must keep honoring its operator's documented vault_custody = \"file\""
);

/// Whether the KEK sealing this gateway's credentials is the PUBLIC dev constant rather than a real
/// per-install or injected secret: the earlier failure where a live hosted worker sealed customer secrets
/// under a passphrase printed in this file.
///
/// The crypto being right and the key being wrong is invisible to every protocol test, so this is an
/// assertion about the running process's boot state or it is nothing. Reported by `/health`; safe to
/// expose, because it says only *which class* of key is in use, and the dev constant's value is
/// already public.
///
/// Calling this cannot change the answer: the passphrase is resolved once at boot (the secret backend
/// and the store's open path both take it), so by the time anything can ask, it is decided.
pub fn vault_kek_is_dev() -> bool {
    vault_passphrase() == DEV_VAULT_PASSPHRASE
}

/// Why a gateway with no route to a real vault KEK refuses to start, and what to do about it.
const NO_KEK_REFUSAL: &str = "refusing to start: no vault KEK is available, and a gateway cannot hold credentials without one. \
     Permaura normally generates one at ~/.permaura/vault-kek on first run; that failed here, so the home directory is probably unwritable or unset (check PERMAURA_HOME). \
     Hand one over at a path with PERMAURA_VAULT_PASSPHRASE_FILE, or on stdin with PERMAURA_VAULT_PASSPHRASE_STDIN=1, or set PERMAURA_ALLOW_INSECURE_VAULT=1 to run with NO at-rest encryption on a throwaway install.";

/// Read (or first-time generate) this install's vault KEK from the best custody the machine offers,
/// so a gateway that wasn't handed one seals under a real per-install secret instead of the public
/// dev constant.
///
/// `Err` is NOT "no key here". It is the custody layer refusing to answer for a key it has recorded
/// as being in a store that has gone quiet, and it must reach the caller intact: falling through to a
/// freshly minted key at that point is precisely the failure of a gateway that comes up healthy having re-keyed
/// a vault it can no longer open.
///
/// Minting is refused while the store this gateway opens already holds credentials sealed under a
/// real key. The custody marker cannot say that for a store kept outside the home, or
/// once the marker itself is gone, and those are exactly the installs a fresh key would orphan.
fn persistent_install_kek() -> Result<Vec<u8>, String> {
    VAULT_KEK_CUSTODY
        .resolve_or_create_unless(|| match crate::store_path_from_env() {
            Some(store) => what_a_fresh_kek_would_orphan(&store),
            None => Ok(None),
        })
        .map(String::into_bytes)
}

/// The sentence the mint refusal ends with, when the store at `store` holds credentials a fresh KEK
/// could never open, or `None` when it holds none.
fn what_a_fresh_kek_would_orphan(store: &str) -> Result<Option<String>, String> {
    #[cfg(feature = "sqlite")]
    let sealed = crate::store::sqlite::credentials_sealed_under_a_real_kek(store).map_err(|e| format!("{store} could not be read: {e}"))?;
    #[cfg(not(feature = "sqlite"))]
    let sealed = 0usize;
    if sealed == 0 {
        return Ok(None);
    }
    let home_key = VAULT_KEK_CUSTODY.path().map(|p| p.display().to_string()).unwrap_or_else(|_| "the Permaura home".into());
    Ok(Some(format!(
        "{store} holds {sealed} credential{} sealed under the missing one. If the original key is somewhere, hand it over with PERMAURA_VAULT_PASSPHRASE_FILE or put it back at {home_key}. If it is genuinely gone, those credentials cannot be recovered: moving {store} aside, or running `permaura uninstall --purge-data` when it is the home's own store, starts a fresh vault",
        if sealed == 1 { "" } else { "s" }
    )))
}

#[cfg(test)]
mod vault_kek_tests {
    use super::*;

    /// `PERMAURA_DEV` is a developer's switch. A release binary or a hosted worker that inherits it
    /// from a stray environment must not seal a customer's credentials under a constant printed here.
    #[test]
    fn the_dev_kek_is_honored_only_in_a_debug_build_that_is_not_hosted() {
        assert_eq!(dev_kek(false, true, false), DevKek::NotRequested);
        assert_eq!(dev_kek(false, false, true), DevKek::NotRequested);
        assert_eq!(dev_kek(true, true, false), DevKek::Honored);
        assert_eq!(dev_kek(true, false, false), DevKek::IgnoredInRelease);
        assert_eq!(dev_kek(true, true, true), DevKek::IgnoredWhenHosted);
        assert_eq!(dev_kek(true, false, true), DevKek::IgnoredWhenHosted);
    }

    /// The order is the whole point, so it is asserted rather than left to reading order.
    /// The inline variable no longer competes at all: it resolves to [`Handover::Ignored`], which
    /// carries no value, so no ordering change can put the KEK back somewhere every same-user
    /// process can read.
    #[test]
    fn the_safest_hand_over_route_on_offer_is_the_one_taken() {
        let f = || Some("/run/secrets/kek".to_string());
        let i = || Some("inline-secret".to_string());

        assert_eq!(handover_from(true, f(), i()), Handover::Stdin, "stdin beats both");
        assert_eq!(handover_from(true, None, None), Handover::Stdin);
        assert_eq!(
            handover_from(false, f(), i()),
            Handover::File("/run/secrets/kek".into()),
            "a mounted path beats the environment variable"
        );
        assert_eq!(handover_from(false, None, i()), Handover::Ignored);
        assert_eq!(handover_from(false, None, None), Handover::None);
    }

    /// The inline hand-over is deleted, not deprioritised. A deployment that still sets the variable
    /// must be told, because the gateway now resolves a DIFFERENT key and a vault sealed under the
    /// inline value will not open; a silent fall-through would look like data loss.
    #[test]
    fn the_inline_variable_is_ignored_and_carries_no_value() {
        let route = handover_from(false, None, Some("still-set-by-an-old-deployment".into()));
        assert_eq!(route, Handover::Ignored);
        assert!(
            !format!("{route:?}").contains("still-set-by-an-old-deployment"),
            "the ignored route must not carry the secret: {route:?}"
        );
    }

    /// An empty value is a broken mount or a variable someone cleared, not an offer. Treating one as a
    /// hand-over would seal a vault under nothing and report success.
    #[test]
    fn an_empty_value_is_not_a_hand_over() {
        assert_eq!(handover_from(false, Some(String::new()), None), Handover::None);
        assert_eq!(handover_from(false, None, Some(String::new())), Handover::None);
        assert_eq!(
            handover_from(false, Some(String::new()), Some("real".into())),
            Handover::Ignored,
            "an empty path falls through to the ignored-variable warning, not to silence"
        );
    }

    /// The mapping `/health` reports, in the one configuration where the answer is known: a test
    /// build takes the dev constant silently, so `dev` is what an honest field must say. An inverted
    /// predicate here would put a green `real` on every gateway sealing under a published key,
    /// strictly worse than not having the field, because it stops anyone looking.
    #[test]
    fn a_gateway_on_the_dev_constant_says_so() {
        assert!(vault_kek_is_dev());
    }

    #[test]
    fn a_hand_over_loses_its_trailing_newline_and_nothing_else() {
        assert_eq!(trim_trailing_newlines(b"secret\n".to_vec()), Some(b"secret".to_vec()));
        assert_eq!(trim_trailing_newlines(b"secret\r\n".to_vec()), Some(b"secret".to_vec()));
        assert_eq!(trim_trailing_newlines(b"secret".to_vec()), Some(b"secret".to_vec()));
        // Interior newlines belong to the key. A base64 KEK will not contain one, but silently
        // truncating at the first is the kind of thing that half-opens a vault.
        assert_eq!(trim_trailing_newlines(b"a\nb\n".to_vec()), Some(b"a\nb".to_vec()));
        assert_eq!(trim_trailing_newlines(b"\n\n".to_vec()), None, "a pipe with only newlines is empty");
        assert_eq!(trim_trailing_newlines(Vec::new()), None);
    }

    /// Where the KEK is addressed is a compatibility contract, not a naming choice. Every install
    /// that has ever adopted found its key under exactly these three strings, and a rename does not
    /// fail: it reports first run and mints over a live vault. `com.permaura.desktop` is historical
    /// (the desktop app held this in earlier builds) and stays for that reason alone.
    #[test]
    fn the_kek_is_addressed_where_existing_installs_already_keep_it() {
        assert_eq!(VAULT_KEK_CUSTODY.service, "com.permaura.desktop");
        assert_eq!(VAULT_KEK_CUSTODY.account, "vault-kek");
        assert_eq!(VAULT_KEK_CUSTODY.file_name, "vault-kek");
        assert!(
            VAULT_KEK_CUSTODY.needs_stable_code_identity,
            "a gateway can be started headless, where a Keychain prompt cannot be answered"
        );
    }

    /// A hand-over somebody asked for and did not get is a refusal, never `None`,
    /// because `None` lets the caller resolve (and on a first-looking home, mint) a different key.
    #[test]
    fn a_requested_hand_over_that_delivers_nothing_is_an_error_not_a_fall_through() {
        let no_file = |_: &str| -> std::io::Result<Vec<u8>> { panic!("the file is not read on this route") };
        let no_stdin = || -> Result<Vec<u8>, String> { panic!("stdin is not read on this route") };

        let why = handed_over(&Handover::Stdin, || Err("stdin closed without a key".into()), no_file).unwrap_err();
        assert!(why.contains("PERMAURA_VAULT_PASSPHRASE_STDIN") && why.contains("stdin closed without a key"), "{why}");

        let file = Handover::File("/run/secrets/kek".into());
        let why = handed_over(&file, no_stdin, |_| Ok(b"\n".to_vec())).unwrap_err();
        assert!(why.contains("/run/secrets/kek") && why.contains("empty"), "{why}");
        let why = handed_over(&file, no_stdin, |_| Err(std::io::Error::from(std::io::ErrorKind::NotFound))).unwrap_err();
        assert!(why.contains("PERMAURA_VAULT_PASSPHRASE_FILE") && why.contains("could not be read"), "{why}");
        assert!(why.contains("different key"), "and it says what carrying on would cost: {why}");

        assert_eq!(handed_over(&file, no_stdin, |_| Ok(b"the-key\n".to_vec())).unwrap(), Some(b"the-key".to_vec()));
        assert_eq!(handed_over(&Handover::Stdin, || Ok(b"piped".to_vec()), no_file).unwrap(), Some(b"piped".to_vec()));
        assert_eq!(handed_over(&Handover::None, no_stdin, no_file).unwrap(), None);
        assert_eq!(handed_over(&Handover::Ignored, no_stdin, no_file).unwrap(), None);
    }

    /// What the mint refusal counts: credentials under a real key. Dev-sealed ones are the re-seal
    /// sweep's to move, and no store or an empty one is a first run.
    #[cfg(feature = "sqlite")]
    #[test]
    fn only_credentials_sealed_under_a_real_kek_stop_a_mint() {
        use permaura_core::crypto::{seal, Cipher};
        let dir = std::env::temp_dir().join(format!("permaura-kek-orphan-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gateway.db").to_string_lossy().to_string();
        assert_eq!(what_a_fresh_kek_would_orphan(&db).unwrap(), None, "no store is a first run");
        assert_eq!(what_a_fresh_kek_would_orphan(":memory:").unwrap(), None);

        let store = crate::store::sqlite::SqliteStore::open(&db).unwrap();
        assert_eq!(what_a_fresh_kek_would_orphan(&db).unwrap(), None, "an empty store is a first run");
        let record = |id: &str, kek: &[u8]| permaura_core::SecretRecord {
            id: id.into(),
            sealed: seal(Cipher::Aes256Gcm, kek, b"value").unwrap(),
            metadata: Default::default(),
        };
        store.put_secret(record("sec_dev", DEV_VAULT_PASSPHRASE)).unwrap();
        assert_eq!(what_a_fresh_kek_would_orphan(&db).unwrap(), None, "the sweep moves a dev-sealed credential");
        store.put_secret(record("sec_real", b"some-real-kek")).unwrap();
        let what = what_a_fresh_kek_would_orphan(&db).unwrap().expect("a real-sealed credential stops it");
        assert!(what.contains(&db) && what.contains("1 credential sealed"), "{what}");
        assert!(what.contains("PERMAURA_VAULT_PASSPHRASE_FILE") && what.contains("moving"), "and says the two ways forward: {what}");

        drop(store);
        std::fs::write(&db, b"not a database").unwrap();
        assert!(what_a_fresh_kek_would_orphan(&db).is_err(), "a store that cannot be read is not an empty one");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The inline variable is ignored now, so the refusal must not send anyone to it.
    #[test]
    fn the_no_kek_refusal_names_only_hand_overs_that_work() {
        assert!(NO_KEK_REFUSAL.contains("PERMAURA_VAULT_PASSPHRASE_FILE"), "{NO_KEK_REFUSAL}");
        assert!(NO_KEK_REFUSAL.contains("PERMAURA_VAULT_PASSPHRASE_STDIN=1"), "{NO_KEK_REFUSAL}");
        let bare = NO_KEK_REFUSAL
            .match_indices("PERMAURA_VAULT_PASSPHRASE")
            .filter(|(i, _)| !NO_KEK_REFUSAL[i + "PERMAURA_VAULT_PASSPHRASE".len()..].starts_with('_'))
            .count();
        assert_eq!(bare, 0, "it still tells people to set the ignored inline variable: {NO_KEK_REFUSAL}");
    }
}

/// The outcome of an `/v1/invoke` (or `permaura.invoke`) call, before transport
/// shaping. Mirrors the three policy verdicts so REST can map them to 200 / 202 / 403
/// and MCP can render them into a JSON-RPC result.
pub enum InvokeOutcome {
    /// Allowed and executed; carries the redacted upstream result and the decision.
    Allowed {
        /// The policy decision (always `allow`).
        decision: Decision,
        /// The redacted upstream response body, as its text: key-name redaction applied, and the
        /// injected credential scrubbed by value when it is 8 bytes or more, in the encodings
        /// [`CredentialScrub`] covers.
        result: JsonText,
        /// The upstream HTTP status code.
        status: u16,
        /// The room `result` takes in the view-growth budget past what its execution's slot holds. A route keeps it with the response until the response has been sent ([`crate::delivery::HoldWhileSending`]), since the body holds the view's bytes until the client reads them; a relayed invoke keeps it only until its result has been framed, and sends the framed result without it.
        room: MemoryCharge,
    },
    /// Escalated to a human; carries the pending approval and the decision.
    RequiresApproval {
        /// The policy decision (`requires_approval`, with its approval requirement).
        decision: Decision,
        /// The recorded pending approval the human will resolve.
        approval: PendingApproval,
    },
    /// Denied; carries the decision with its reason.
    Denied {
        /// The policy decision (`deny`).
        decision: Decision,
    },
}

/// The store, device registry and keyring a held change's title takes its names from. A failed read
/// names the thing by id rather than failing the hold.
struct HoldNames<'a> {
    service: &'a EnforcementService,
}

impl HoldNames<'_> {
    fn found<T>(read: Result<Option<T>, GatewayError>, name: impl FnOnce(T) -> String) -> Stored {
        match read {
            Ok(Some(record)) => Stored::Found(name(record)),
            Ok(None) => Stored::Missing,
            Err(_) => Stored::Unknown,
        }
    }

    fn connection_name(c: permaura_core::Connection) -> String {
        crate::policy_guard::connection_display_name(&c.label, &c.name)
    }
}

impl MutationNames for HoldNames<'_> {
    fn connection(&self, id: &str) -> Stored {
        Self::found(self.service.store.get_connection(id), Self::connection_name)
    }

    fn policy(&self, id: &str) -> Stored {
        Self::found(self.service.store.get_policy(id), |p| p.name)
    }

    fn grant(&self, grant_id: &str) -> Stored {
        Self::found(self.service.store.get_grant(grant_id), |g| g.name)
    }

    fn agent(&self, id: &str) -> Stored {
        Self::found(self.service.store.get_agent(id), |a| a.name)
    }

    fn secret_owner(&self, secret_id: &str) -> Stored {
        let store = self.service.store.as_ref();
        match store.list_connections().map(|cs| cs.into_iter().find(|c| c.secret_id == secret_id)) {
            Ok(Some(c)) => Stored::Found(Self::connection_name(c)),
            Ok(None) => match store.list_capabilities().map(|caps| caps.into_iter().find(|c| c.secret_id == secret_id)) {
                Ok(Some(cap)) => self.connection(&cap.resource),
                Ok(None) => Stored::Missing,
                Err(_) => Stored::Unknown,
            },
            Err(_) => Stored::Unknown,
        }
    }

    // A revoked registry row still carries the name the owner knows the device by, which is what a
    // title removing that device's key needs when the row was revoked first.
    fn device(&self, approver_id: &str) -> Stored {
        let signs_as = |d: &crate::push::Device| d.approver_id.as_deref() == Some(approver_id);
        let device = self.service.push.find_by_approver(approver_id).or_else(|| self.service.push.list().into_iter().rev().find(signs_as));
        match device {
            Some(d) => Stored::Found(d.name),
            None => Stored::Missing,
        }
    }

    fn displaced_key(&self, approver_id: &str, new_key: &str) -> Option<String> {
        self.service
            .approver_keyring_snapshot()
            .trusted_key(approver_id)
            .filter(|k| *k != new_key)
            .map(str::to_string)
    }

    fn last_trusted_device(&self, approver_id: &str) -> bool {
        self.service.revoking_would_empty_keyring(approver_id)
    }

    fn policy_record(&self, id: &str) -> Option<permaura_core::Policy> {
        self.service.store.get_policy(id).ok().flatten()
    }

    fn grant_record(&self, grant_id: &str) -> Option<permaura_core::Grant> {
        self.service.store.get_grant(grant_id).ok().flatten()
    }

    fn grants_including(&self, policy_id: &str) -> Option<Vec<String>> {
        let grants = self.service.store.list_grants().ok()?;
        Some(grants.into_iter().filter(|g| g.policy_ids.iter().any(|p| p == policy_id)).map(|g| g.grant_id).collect())
    }

    fn connection_hosts(&self, id: &str) -> Vec<String> {
        crate::rest::connection_pins(self.service.store.as_ref(), id).map(|(_, hosts)| hosts).unwrap_or_default()
    }
}

/// A digest of the sorted estate with the quorums in force under it.
type InForce = ([u8; 32], std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>);

const IN_FORCE_KEPT: usize = 4;

fn estate_digest(policies: &[permaura_core::Policy], grants: &[permaura_core::Grant]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut policies: Vec<_> = policies.iter().collect();
    let mut grants: Vec<_> = grants.iter().collect();
    policies.sort_by(|a, b| a.id.cmp(&b.id));
    grants.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    Sha256::digest(serde_json::to_vec(&(policies, grants)).expect("stored estate serializes")).into()
}

/// `marks` raised to every quorum in `in_force`.
fn raised_marks(
    mut marks: std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>,
    in_force: &std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>,
) -> std::collections::BTreeMap<crate::policy_guard::ActionKey, u8> {
    for (key, q) in in_force {
        let mark = marks.entry(key.clone()).or_insert(*q);
        *mark = (*mark).max(*q);
    }
    marks
}

/// The effect and the full estate used to classify a held change, stored together before its approval row.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct HeldEffectRecord {
    effect: crate::policy_guard::HeldEffect,
    estate_digest: Option<[u8; 32]>,
}

/// An unfinished comparison can authorize only the same estate; older holds without a digest must be asked for again.
fn effect_widened(kept: Option<&HeldEffectRecord>, now: &HeldEffectRecord) -> Option<String> {
    use crate::policy_guard::{HeldEffect, Loosening};
    let unknown = matches!(now.effect, HeldEffect::PastBudget) || kept.is_some_and(|r| matches!(r.effect, HeldEffect::PastBudget));
    if !unknown && matches!(now.effect, HeldEffect::NotBinding) {
        return None;
    }
    let Some(kept) = kept.filter(|r| r.estate_digest.is_some()) else {
        return Some("the estate at the time this change was held was not recorded".into());
    };
    if unknown {
        return (kept.estate_digest != now.estate_digest)
            .then(|| "the estate changed and its effect cannot be compared within the classification budget".into());
    }
    match (&kept.effect, &now.effect) {
        (HeldEffect::Lowers(then), HeldEffect::Lowers(now)) => then.widened_in(now),
        (_, HeldEffect::Lowers(now)) => Loosening::default().widened_in(now),
        _ => None,
    }
}

/// The quorum of a change the estate cannot raise, for the synchronous ways to hold one.
fn estate_free_quorum(mutation: &crate::policy_guard::Mutation) -> Result<u8, GatewayError> {
    crate::policy_guard::quorum_without_estate(mutation).ok_or_else(|| {
        GatewayError::Internal("a change whose quorum is worked out from the estate is held through hold_change_approval".into())
    })
}

/// The shared enforcement service. Holds the store, the HTTP client used to reach upstream
/// APIs, and the command runner used to drive locked-down CLIs. The HTTP client is always
/// supplied by the caller; the command runner defaults to a deterministic mock in [`Self::new`],
/// and the SSH runner in every constructor, until one is wired in. A shipped gateway wires the
/// real HTTP client, command runner and SSH runner, while the demo and tests wire mocks.
///
/// `Clone` is a **handle**, not a copy: every field is an `Arc` or a plain flag read at
/// construction, so two clones drive the same store, the same keyring and the same kill switch.
/// It exists so [`Self::invoke`] can move a handle into the task that owns an execution and the
/// terminal audit event that must follow it; a clone that forked any of this state would put two
/// answers behind one workspace.
#[derive(Clone)]
pub struct EnforcementService {
    store: Arc<dyn Store>,
    http: Arc<dyn HttpClient>,
    command: Arc<dyn CommandRunner>,
    /// The SSH/SFTP transport used by [`CapabilityKind::Ssh`] capabilities. Defaults to a
    /// deterministic [`connectors::MockSshRunner`] so the gateway never opens a real SSH
    /// connection unless a real runner is wired in via [`EnforcementService::with_ssh_runner`].
    ssh: Arc<dyn SshRunner>,
    push: Arc<crate::push::DeviceRegistry>,
    /// Who this gateway announces holds to, if anyone. Shared by every clone, so a link applied
    /// through one handle is the answer every hold site reads.
    announcer: Arc<crate::announce::Announcer>,
    /// The custody seam: turns a `secret_id` into plaintext for one call. Defaults to a
    /// [`LocalVaultBackend`] over the same store; later milestones inject external
    /// backends (Infisical / KMS / …) here without touching the enforcement loop.
    backend: Arc<dyn SecretBackend>,
    /// Global operator kill switch. When set, every agent invoke is denied above all policy,
    /// while the gateway stays up so the operator can still read state and unpause. Recorded in
    /// the store and read back at construction, so a restart does not lift it; the operator flips
    /// it via `POST /v1/broker/pause`.
    paused: Arc<AtomicBool>,
    /// Every agent paused by the deployment rather than the operator (`PERMAURA_AGENTS_PAUSED`): the hosted control plane sets it through a lapse's grace and a decommission, so neither the owner nor a stored session can lift it. Read once at boot; a Cloud Run environment change is a new revision.
    agents_paused: Arc<AtomicBool>,
    /// The new-agent gate: while it is on, a **new** OAuth-authenticated agent lands as
    /// [`AgentStatus::Pending`] (invokes denied) until an operator approves it, even though the AS
    /// consent already happened. One of the `AGENT_GATE_*` states: unset, it follows
    /// [`Self::agent_gate_default`]; the operator's choice through
    /// `POST /v1/broker/require-approval` is recorded in the store like [`Self::paused`] and always
    /// wins; `PERMAURA_REQUIRE_AGENT_APPROVAL` engages it for one run. Never auto-approves an agent an
    /// operator left Pending.
    require_agent_approval: Arc<AtomicU8>,
    /// Whether a device signature that names no gateway (the v1 approval-result and device-control
    /// preimages) is still accepted. Off by default: such a signature could have been
    /// collected by any gateway that trusts the same device key. `PERMAURA_ACCEPT_V1_DEVICE_SIGNATURES=1`
    /// turns it back on for an approver app that predates the audience. Even while it is on, an
    /// approver that has once signed v2 here is held to v2 (see [`Self::device_signature_version_refusal`]).
    accept_v1_device_signatures: Arc<AtomicBool>,
    /// Whether every device-signed APPROVE must bind the parameters the approver was shown (a v3
    /// signature). On by default; `PERMAURA_REQUIRE_DISPLAY_BOUND_APPROVALS=0` turns it off for
    /// an app that predates the rendering. Even while it is off, an approver that has signed v3 here is
    /// held to it.
    require_display_bound_approvals: Arc<AtomicBool>,
    /// The OAuth Resource Server, when the gateway has a public URL. Validates permaura.com-issued
    /// access-token JWTs so remote MCP clients authenticate at the AS and talk to the gateway
    /// directly. `None` for a pure-local gateway (opaque tokens only).
    oauth: Option<Arc<crate::oauth::OAuthRs>>,
    /// The worker-local set of trusted approver device keys, seeded from `PERMAURA_APPROVER_KEYS`
    /// and any persisted pairings and changed only through the guarded pairing and revocation
    /// funnels. On a self-run gateway a key is added only by a loopback request, on its own for the
    /// first device and with a trusted device's co-signature for every later one, so the control
    /// plane cannot add one; on a hosted worker the first key is enrolled on a permaura.com owner
    /// step-up ticket, so whoever controls permaura.com's ticket signing or the worker's
    /// `PERMAURA_APPROVER_KEYS` can make an empty keyring trust its key. Shared by the REST approval
    /// verifier and the relay path so both check against the same keyring.
    approver_keyring: Arc<RwLock<ApproverKeyring>>,
    /// The operator's explicit **approval floor** override, or `None` for the default (in which case
    /// enrolment decides; see [`Self::approval_floor`]). `Some(Approve)` is the opt-DOWN that
    /// re-enables bearer-resolvable `approve`-tier approvals after a device is paired; it is a
    /// trust-root control, mutated only over loopback. Persisted alongside the keyring.
    approval_floor: Arc<RwLock<Option<ApprovalFloor>>>,
    /// Where the keyring and its floor override are persisted. Selected once at construction (see
    /// [`KeyringPersistence`]) and never changed afterwards, so every read and write in the process
    /// agrees about which backend holds the trust state.
    keyring_persistence: KeyringPersistence,
    /// Whether this is a hosted (Mode C) worker. Captured once rather than read from the environment
    /// at call time, because `PERMAURA_HOSTED` is process-global and the tests run in parallel.
    hosted: bool,
    /// Wall-clock milliseconds at which this process last *attempted* to reload the keyring and floor
    /// from [`Self::keyring_persistence`]. Only meaningful under [`KeyringPersistence::Store`], where
    /// another instance of the same worker can have paired or revoked a device since this instance
    /// loaded; see [`Self::refresh_keyring_if_stale`]. It records the attempt rather than the last
    /// success so a store outage degrades to last-known-good instead of a read on every request.
    keyring_loaded_at: Arc<AtomicI64>,
    /// Serialises control-plane mutations (the broker-guard classify→hold-or-apply critical section)
    /// so the store snapshot a classifier reads cannot shift between the classification and the apply
    /// (the classifier↔apply TOCTOU). Rare, operator-authed writes: a coarse lock is cheap.
    control_plane_lock: Arc<tokio::sync::Mutex<()>>,
    /// The quorums in force under the last few estates a change resolved on the blocking pool, so the marks its apply
    /// notes and settles read them instead of resolving the estate on a runtime worker. Keyed by the estate itself; a
    /// miss resolves inline. An entry read a moment later can only count a rule whose grant has since ended, which
    /// asks for more signatures, never fewer.
    in_force_cache: Arc<std::sync::Mutex<Vec<InForce>>>,
    classification_slots: Arc<tokio::sync::Semaphore>,
    /// Serialises the record-signature→count-quorum step of [`Self::verify_signed_approval`], so
    /// two devices signing at the same instant cannot both observe the quorum completing and both
    /// go on to run the held call. A `std::sync::Mutex` deliberately: the section is pure store
    /// access with no await inside it.
    signature_lock: Arc<std::sync::Mutex<()>>,
    /// Serialises the read-modify-write of the persisted keyring; see [`Self::mutate_keyring`],
    /// which is the ONLY thing allowed to take it. A `std::sync::Mutex` for the same reason
    /// [`Self::signature_lock`] is one (the section is pure store access with no await), and a
    /// separate lock from [`Self::control_plane_lock`] because revocation is a synchronous path
    /// that never enters the async broker guard.
    keyring_write_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes the read-modify-write of the approvers that have signed v2 or v3; see
    /// [`Self::note_v2_signer`] and [`Self::note_display_signer`].
    v2_signers_lock: Arc<std::sync::Mutex<()>>,
    /// Serializes the slot check, the Secrets allowance count and the insert of every secret row a write can add; see [`Self::publish_secret`] and [`Self::lock_secret_publication`].
    secret_publication_lock: Arc<std::sync::Mutex<()>>,
    /// The per-tenant execution hold, when this gateway has one configured. `None` on every local
    /// gateway and on any hosted worker with neither layer set. See [`crate::restore`].
    execution_hold: Option<Arc<crate::restore::ExecutionHold>>,
    /// The hot audit store's warning band and hard ceiling. Always present, unlike the hold: every
    /// gateway has a chain and every chain grows. See [`crate::audit_ceiling`].
    audit_ceiling: Arc<crate::audit_ceiling::AuditCeiling>,
    /// The per-tenant count ceilings on agents, secrets, grants and connections. Always present and
    /// unlimited unless a provisioner sets the four variables, so a self-hosted gateway never meets
    /// one. See [`crate::allowances`].
    allowances: Arc<crate::allowances::Allowances>,
    /// Grant budget held by executions that have passed policy but not yet appended the terminal
    /// event that charges it. See [`BudgetBook`].
    budget_book: Arc<std::sync::Mutex<BudgetBook>>,
    /// The archive writer, when `PERMAURA_AUDIT_ARCHIVE=1` and a bucket is configured. `None`
    /// everywhere else, and then nothing is published and nothing is pruned: the flag off is
    /// byte-identical to a gateway that has never heard of an archive. See [`crate::archive`].
    audit_archive: Option<Arc<crate::archive::AuditArchive>>,
    /// The executions this process has admitted and not finished, and whether it still admits any.
    /// Shared by every clone, so the drain sees the relay's and the router's alike. See [`crate::drain`].
    executions: Arc<crate::drain::Executions>,
    /// One async lock per secret id, taken by an invocation about to refresh that secret's OAuth
    /// credential, so two calls on one expiring credential send one refresh and a different
    /// credential's refresh never waits on it. Created on demand; see [`Self::fresh_oauth_credential`].
    oauth_refresh_slots: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Rotated OAuth bundles the store refused to write, by secret id. See [`PendingRotation`].
    oauth_pending_rotations: PendingRotations,
    /// Deliberate changes to the credential slots a connector OAuth dance is outstanding against. See [`crate::oauth_connect::CredentialRevisions`].
    credential_revisions: Arc<crate::oauth_connect::CredentialRevisions>,
    /// The worker's budget for the JSON trees its calls hold, and the budgets a held call is kept to. Shared by every clone. See [`crate::memory`].
    memory: crate::memory::MemoryBudget,
    /// The execution slots the router admits agent calls under, one of which an approved held call takes before it runs only when its params and a slot's share of byte buffers could never fit the pool together ([`Self::approved_call_slot`]). Attached by [`crate::AppState`]; `None` on a service no router admits calls for, whose approved calls always reserve a slot's share in the pool.
    execution_slots: Arc<std::sync::RwLock<Option<Arc<crate::limits::Limits>>>>,
    /// The connector revocation state the gateway booted under. Attached by [`crate::AppState`]; empty on a service built without one.
    pmconn_revocation: Arc<std::sync::RwLock<Arc<crate::manifest::Revocation>>>,
}

/// A refreshed OAuth bundle the store refused to write.
///
/// A provider that rotates refresh tokens spent the stored one when it answered, so this is the only
/// live copy of the credential. It is kept in memory, used in place of the stored bundle, and written
/// by the next refresh round of the same secret that finds the store accepting writes, compare-and-swap
/// over the envelope it was refreshed from. A replacement written meanwhile (a new authorization) wins
/// and the pending rotation is dropped. Memory is all it has: if this process stops before the write
/// lands, the stored bundle still names the spent token, the provider refuses the next refresh and the
/// connection must be authorized again. Only the sealed envelope is kept, opened when a round uses it, and
/// the entry goes when its secret is deleted.
#[derive(Clone)]
struct PendingRotation {
    expected: SealedSecret,
    sealed: SealedSecret,
}

type PendingRotations = Arc<std::sync::Mutex<std::collections::HashMap<String, PendingRotation>>>;

/// How long a refresh round keeps retrying a write the store refused before it parks the rotation.
const ROTATION_WRITE_RETRIES: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(50),
    std::time::Duration::from_millis(200),
    std::time::Duration::from_millis(800),
];

/// Whether `sub` could be an account id permaura.com minted: the shape `PERMAURA_OWNER_SUB` takes, and nothing a config file or a log line would choke on.
fn owner_sub_well_formed(sub: &str) -> bool {
    !sub.is_empty() && sub.len() <= 128 && sub.chars().all(|c| c.is_ascii_alphanumeric() || "_-.:@".contains(c))
}

/// The audit action a guarded change to the approval floor is recorded under.
pub const APPROVAL_FLOOR_ACTION: &str = "permaura.approval_floor.set";

/// The audit action recorded when the new-agent gate changes with no operator choice behind it: its default followed a device being trusted, or the last one revoked.
pub const AGENT_GATE_DEFAULT_ACTION: &str = "permaura.agent_gate.default";

/// The audit action recorded when the operator this gateway accepts tokens for moves to the owner permaura.com named at a check-in.
pub const OWNER_REPIN_ACTION: &str = "permaura.owner.repin";

/// The audit action recorded when a session is opened, the resource its id: an operator session through `POST /v1/sessions`, or the agent session an OAuth agent's first call opens.
pub const SESSION_OPEN_ACTION: &str = "permaura.session.open";

/// The audit action recorded when a session is revoked over REST or MCP, the resource its id.
pub const SESSION_REVOKE_ACTION: &str = "permaura.session.revoke";

/// The audit action recorded when an operator mints an enrolment code.
pub const ENROLMENT_CODE_MINT_ACTION: &str = "permaura.enrolment_code.mint";

/// The audit action recorded when an enrolment code is redeemed into a new agent and its bearer, the resource the agent's id.
pub const AGENT_ENROLL_ACTION: &str = "permaura.agent.enroll";

const AGENT_GATE_UNSET: u8 = 0;
const AGENT_GATE_STORED_OFF: u8 = 1;
const AGENT_GATE_STORED_ON: u8 = 2;
const AGENT_GATE_THIS_RUN: u8 = 3;

/// What minting or redeeming an enrolment code is told while `PERMAURA_AGENTS_PAUSED` is set.
pub const AGENTS_PAUSED_ENROLMENT_MESSAGE: &str = "agents are paused on this gateway: its hosted plan has lapsed or it is being removed, so no agent can be enrolled until agents resume, once the plan is paid or the removal is canceled. Agents already enrolled stay enrolled.";

/// What an agent, or an execution, is told while `PERMAURA_AGENTS_PAUSED` is set.
pub const AGENTS_PAUSED_MESSAGE: &str = "agents are paused on this gateway: its hosted plan has lapsed or it is being removed, so nothing was executed. The owner can still sign in to the console and export the vault. Agents resume, still enrolled, once the plan is paid or the removal is canceled.";

/// Where the new-agent gate's value comes from, as `GET /v1/broker` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentGateSource {
    /// Nothing is stored: the gate follows [`EnforcementService::agent_gate_default`].
    Default,
    /// The operator's choice, recorded in the store.
    Stored,
    /// `PERMAURA_REQUIRE_AGENT_APPROVAL` engaged it for this run.
    Environment,
}

impl AgentGateSource {
    /// The name `GET /v1/broker` reports.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentGateSource::Default => "default",
            AgentGateSource::Stored => "stored",
            AgentGateSource::Environment => "environment",
        }
    }
}

/// The worker's floor for what a **bare operator bearer** may resolve. `DeviceSigned` means every
/// bearer-only resolution is refused (only a device signature resolves anything); `Approve` means a
/// bearer may resolve `approve`-tier approvals but never a `device_signed`-tier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFloor {
    /// A bearer may resolve `approve`-tier approvals; `device_signed`-tier still needs a signature.
    Approve,
    /// No bearer resolution at all: a device signature is required for every approval.
    DeviceSigned,
}

impl ApprovalFloor {
    /// Parse the persisted / wire form.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "approve" => Some(ApprovalFloor::Approve),
            "device_signed" => Some(ApprovalFloor::DeviceSigned),
            _ => None,
        }
    }
    /// The persisted / wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalFloor::Approve => "approve",
            ApprovalFloor::DeviceSigned => "device_signed",
        }
    }
}

/// Where the approver keyring and its approval-floor override are kept between requests.
///
/// The two facts are the trust root of the human-approval gate, and losing them does not merely
/// forget a convenience: [`EnforcementService::approval_floor`] derives `DeviceSigned` from
/// `ever_enrolled()`, so an empty keyring reads as "nothing was ever paired" and the floor silently
/// falls back to `Approve`: bearer-only approval resolution re-opens on an install whose owner
/// believes a phone is required. That is a fail-OPEN, which is why every gateway persists: there is
/// no in-memory backend, because a self-run gateway that forgot its pairings on restart was exactly
/// that failure, reported as a success at pairing time.
#[derive(Clone)]
enum KeyringPersistence {
    /// A JSON file plus a sibling `.floor`, chosen only by an explicit `PERMAURA_APPROVER_KEYS_PATH`.
    File {
        /// The keyring JSON, from `PERMAURA_APPROVER_KEYS_PATH`.
        keys: PathBuf,
        /// The floor override, the same path with a `.floor` extension.
        floor: PathBuf,
    },
    /// `gateway_meta` rows in the gateway's own store: the default everywhere. On a hosted (Mode C)
    /// worker it is the only durable home, since the filesystem does not survive a scale-to-zero and
    /// several Cloud Run instances must agree on which devices are trusted. On a self-run gateway it
    /// rides in `gateway.db` beside everything else the operator already backs up.
    Store,
}

/// How long an instance may serve the keyring and floor it loaded before re-reading them from the
/// store. Only [`KeyringPersistence::Store`] has anything to refresh; the `File` backend cannot be
/// written behind this process's back.
///
/// The window is short because the stale-read failure is not only an availability one. An instance
/// that has not yet seen a pairing rejects that device's signature (annoying), but an instance whose
/// keyring is empty *also* resolves [`EnforcementService::approval_floor`] to `Approve` and will
/// accept a bearer-only resolution the tenant believes is closed (a fail-open). Five seconds bounds
/// that window without turning every approval read into a database round trip.
const KEYRING_REFRESH_MS: i64 = 5_000;

/// The keyring, floor, and persistence backend a constructor installs on the service, produced by
/// [`EnforcementService::build_approver_keyring`] so the three constructors cannot drift apart in how
/// they load trust state.
struct KeyringState {
    keyring: Arc<RwLock<ApproverKeyring>>,
    floor: Arc<RwLock<Option<ApprovalFloor>>>,
    persistence: KeyringPersistence,
    loaded_at: Arc<AtomicI64>,
}

/// The outcome of verifying a device-signed approval, shared by the REST and relay paths so there is
/// exactly one verifier. The caller runs the held call only on [`SignedApprovalOutcome::Verified`].
pub enum SignedApprovalOutcome {
    /// Signature + binding + freshness all check out, the approval is still pending, and this
    /// signature completed the quorum; resolve it. The quorum transition happens under a lock, and
    /// resolution's durable claim makes the held call run once even if a re-delivered signature for an
    /// approval that already has enough people also reports this.
    Verified,
    /// The signature is valid and recorded, but the approval still needs more distinct people
    /// (the two-person rule). The held call must NOT run yet; surface the progress to the signer.
    AwaitingSignatures {
        /// The approval as stored, with this signature now on it.
        approval: PendingApproval,
        /// Distinct people that have signed so far (see [`live_people_count`]).
        collected: u8,
        /// Distinct people the approval needs.
        required: u8,
    },
    /// The approval was already resolved (idempotent re-delivery); surface its terminal state.
    AlreadyResolved(PendingApproval),
    /// Verification failed (unknown/revoked approver, bad signature, stale, expired, hash mismatch,
    /// self-approval). The held call must NOT run; the string is for logging/telemetry, not the caller.
    Refused(String),
}

/// Holds a minted credential's lease until the call it was minted for is over, and makes sure it
/// goes back even on the paths an `await` never reaches.
///
/// [`EnforcementService::with_secret`] releases explicitly on both the success and error paths;
/// this guard exists for the third case, which is the easy one to miss: the whole request future
/// being **dropped** (an axum handler cancelled by a client disconnect or a server timeout) or
/// unwinding on a panic. Without it, exactly the requests that went wrong would be the ones that
/// strand a live credential for the rest of its TTL.
struct LeaseGuard {
    backend: Arc<dyn SecretBackend>,
    lease: Option<Lease>,
}

impl LeaseGuard {
    /// The normal path: hand the lease back and await the result, so a failure is logged here
    /// rather than on a detached task.
    async fn release(mut self) {
        let Some(lease) = self.lease.take() else { return };
        self.backend.release(&lease).await;
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else { return };
        // Reached only when the call was cancelled or panicked, so there is no async context left
        // to await in; spawn the release instead. If even that is impossible (no runtime, or the
        // process is going down with it), the lease TTL is the backstop, which is why a dynamic
        // mint always requests one.
        let backend = self.backend.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move { backend.release(&lease).await });
            }
            Err(_) => tracing::warn!(
                lease = %lease.id,
                "a cancelled call left a credential lease with no runtime to revoke it; it will expire on its TTL"
            ),
        }
    }
}

/// How far a signed decision's `decided_at` may sit from the worker's clock before it is rejected as
/// stale, tolerating modest skew. Bounds how late a captured signed decision for a still-pending
/// approval can be replayed (defense in depth on top of the single-use `approval_id`); held agent
/// calls have no TTL of their own.
const DECISION_FRESHNESS_MS: i64 = 5 * 60 * 1000;

/// How many distinct PEOPLE the collected signatures speak for, which is what a quorum counts.
///
/// A signature counts only while its approver remains trusted in the worker's keyring under the very
/// key it verified against. Revocation has to be retroactive within a pending approval: if a device
/// is revoked because it was lost, the half-approval it already contributed must go with it.
///
/// Two devices bound to the same person (an iPhone and the Watch paired through it) count once, so
/// one person cannot satisfy a two-person rule alone. A key bound to nobody, which is every key paired
/// before keys carried a person, counts only when no bound key has signed: it can still complete a
/// single-signature rule, and it can never be the second person, because nothing says it is not the
/// first person's other device. Re-pairing it binds it.
fn live_people_count(keyring: &ApproverKeyring, signatures: &[crate::store::CollectedSignature]) -> u8 {
    let mut people = std::collections::BTreeSet::new();
    let mut unbound = false;
    for s in signatures {
        let live = keyring.trusted_key(&s.approver).is_some_and(|k| key_fingerprint(k) == s.key_fp);
        if !live {
            continue;
        }
        match keyring.person(&s.approver) {
            Some(person) => {
                people.insert(person);
            }
            None => unbound = true,
        }
    }
    let counted = if people.is_empty() { usize::from(unbound) } else { people.len() };
    counted.min(u8::MAX as usize) as u8
}

/// A short, stable fingerprint of a trusted approver public key, for signature distinctness and
/// for showing *which* device signed. The input is already public (an ed25519 verifying key), so
/// this is a readability aid, not a secrecy measure.
///
/// Crate-visible so the broker guard and the REST pairing surface fingerprint a key exactly the way
/// the signature bookkeeping does. Two schemes must never coexist: a pairing ticket is bound to a
/// `pubkey_fp`, and a second scheme would either reject the very key the ticket was minted for or,
/// worse, let a fingerprint computed one way satisfy a check written against the other.
///
/// Hashing the text names one point only because the keyring admits only [`permaura_relay::validate_pubkey`]'s one canonical spelling of each canonically encoded key, which is also what permaura.com's ticket fingerprint hashes.
pub(crate) fn key_fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pubkey_b64.as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// An opaque, stable handle for the person a key approves for, so a console can group one person's
/// devices without the key list naming an account. Equal handles are the same person.
pub(crate) fn person_handle(person: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("permaura-person-handle:v1:{person}").as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

impl EnforcementService {
    /// Choose where this gateway keeps its approver trust state.
    ///
    /// An explicit `PERMAURA_APPROVER_KEYS_PATH` always wins, so an install that chose a file keeps
    /// the exact file it has. Everything else, hosted or self-run, persists in the store. Until 1.3.8 a
    /// self-run gateway with no path configured kept its pairings in memory only, and nothing in the
    /// desktop or the installer set the path, so every restart silently untrusted every device.
    fn keyring_persistence_from_env() -> KeyringPersistence {
        let path = std::env::var("PERMAURA_APPROVER_KEYS_PATH")
            .ok()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        match path {
            // The floor override persists in a sibling file so a loopback opt-down survives a restart.
            Some(keys) => {
                let floor = keys.with_extension("floor");
                KeyringPersistence::File { keys, floor }
            }
            None => KeyringPersistence::Store,
        }
    }

    /// Read the persisted keyring and floor override out of `persistence`. The statically provisioned
    /// `PERMAURA_APPROVER_KEYS` are **not** merged here; the caller does that, because a refresh has
    /// to re-merge them too.
    ///
    /// The two backends fail differently on purpose. A missing keyring FILE yields an empty keyring,
    /// since on a self-run box a missing file legitimately means "nothing paired yet", the disk is not
    /// shared with anyone, and there is no way for that read to be a transient fault; a corrupt or
    /// unreadable file is an error. A store read has neither property, so under
    /// [`KeyringPersistence::Store`] an unreadable or unparseable row is an error and never an empty
    /// keyring. Degrading there would drop every trusted device AND, through `ever_enrolled()`, lower
    /// the approval floor back to `Approve`: a worker that fails to start is strictly better than one
    /// that quietly stops requiring the tenant's phone. `Ok(None)` is the legitimate fresh-worker case.
    fn load_persisted_keyring(
        persistence: &KeyringPersistence,
        store: &Arc<dyn Store>,
    ) -> Result<(ApproverKeyring, Option<ApprovalFloor>), GatewayError> {
        match persistence {
            KeyringPersistence::File { keys, floor } => {
                let keyring = ApproverKeyring::load(keys).map_err(|e| {
                    GatewayError::Internal(format!(
                        "the approver keyring file could not be loaded; refusing to continue with an empty keyring, which would untrust every paired device and lower the approval floor: {e}"
                    ))
                })?;
                let floor = match std::fs::read_to_string(floor) {
                    Ok(s) if s.trim().is_empty() => None,
                    Ok(s) => Some(ApprovalFloor::from_str(s.trim()).ok_or_else(|| {
                        GatewayError::Internal(format!(
                            "the persisted approval floor '{}' is not a value this build understands; refusing to guess at a trust-root setting",
                            s.trim()
                        ))
                    })?),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => {
                        return Err(GatewayError::Internal(format!(
                            "the approval floor file could not be read: {e}"
                        )))
                    }
                };
                Ok((keyring, floor))
            }
            KeyringPersistence::Store => {
                let keyring = match store.get_meta(APPROVER_KEYRING_META)? {
                    // A host-side reset clears the row to the empty string, the store having no delete.
                    Some(json) if json.trim().is_empty() => ApproverKeyring::new(),
                    Some(json) => ApproverKeyring::from_json(&json).ok_or_else(|| {
                        GatewayError::Internal(
                            "the persisted approver keyring is not readable JSON; refusing to continue with an empty keyring, which would untrust every paired device and lower the approval floor".into(),
                        )
                    })?,
                    None => ApproverKeyring::new(),
                };
                // A clear is written as the empty string (the store has no delete), so empty and
                // absent must mean the same thing here or a cleared override would read back as a
                // parse failure. A non-empty value this build does not recognise is a different
                // matter: it is a trust-root setting written by something else, and guessing at it
                // is how a worker ends up enforcing a floor nobody chose.
                let floor = match store.get_meta(APPROVAL_FLOOR_META)? {
                    Some(s) if s.trim().is_empty() => None,
                    Some(s) => Some(ApprovalFloor::from_str(&s).ok_or_else(|| {
                        GatewayError::Internal(format!(
                            "the persisted approval floor '{s}' is not a value this build understands; refusing to guess at a trust-root setting"
                        ))
                    })?),
                    None => None,
                };
                Ok((keyring, floor))
            }
        }
    }

    /// Build the shared approver keyring: select the backend, load whatever it holds, then merge the
    /// statically provisioned `PERMAURA_APPROVER_KEYS` on top.
    ///
    /// Fallible because the store-backed load is: see [`Self::load_persisted_keyring`] for why an
    /// unreadable row must abort rather than degrade.
    fn build_approver_keyring(store: &Arc<dyn Store>) -> Result<KeyringState, GatewayError> {
        let persistence = Self::keyring_persistence_from_env();
        let (mut keyring, floor) = Self::load_persisted_keyring(&persistence, store)?;
        if let Ok(env) = std::env::var("PERMAURA_APPROVER_KEYS") {
            keyring.merge_env_str(&env);
        }
        Ok(KeyringState {
            keyring: Arc::new(RwLock::new(keyring)),
            floor: Arc::new(RwLock::new(floor)),
            persistence,
            loaded_at: Arc::new(AtomicI64::new(now_ms())),
        })
    }

    /// [`Self::build_approver_keyring`] for the infallible constructors: a load failure aborts the
    /// process instead of returning a service whose trust state is quietly empty.
    ///
    /// This is a panic rather than a propagated error only because the three constructors and every
    /// `AppState` builder above them are infallible today, and threading a `Result` through them
    /// reaches the daemon and the binary. The behaviour is the one that matters and it matches
    /// [`vault_passphrase`]'s refusal to start without a KEK: a hosted worker whose keyring row will
    /// not load crash-loops loudly, which its operator sees, rather than coming up with an empty
    /// keyring and an approval floor that has silently dropped to `Approve`.
    fn build_approver_keyring_or_abort(store: &Arc<dyn Store>) -> KeyringState {
        Self::build_approver_keyring(store).unwrap_or_else(|e| {
            panic!("refusing to start: the approver keyring could not be loaded: {e}")
        })
    }

    /// Build the service over a store and HTTP client, defaulting the command runner to a
    /// deterministic [`connectors::MockCommandRunner`] so the offline runtime never shells
    /// out unless a real runner is wired in via [`EnforcementService::with_command_runner`].
    pub fn new(store: Arc<dyn Store>, http: Arc<dyn HttpClient>) -> Self {
        let backend: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), vault_passphrase().to_vec()));
        let keys = Self::build_approver_keyring_or_abort(&store);
        let announcer = Arc::new(crate::announce::Announcer::from_env());
        let push = Self::restored_push_registry(&store, !announcer.is_configured());
        let (paused, require_agent_approval) = Self::restored_switches(&store);
        EnforcementService {
            store,
            http,
            command: Arc::new(connectors::MockCommandRunner::new()),
            ssh: Arc::new(MockSshRunner::new()),
            push,
            announcer,
            backend,
            paused: Arc::new(AtomicBool::new(paused)),
            agents_paused: Arc::new(AtomicBool::new(false)),
            require_agent_approval: Arc::new(AtomicU8::new(require_agent_approval)),
            accept_v1_device_signatures: Arc::new(AtomicBool::new(false)),
            require_display_bound_approvals: Arc::new(AtomicBool::new(true)),
            oauth: None,
            approver_keyring: keys.keyring,
            approval_floor: keys.floor,
            keyring_persistence: keys.persistence,
            hosted: crate::hosted_from_env(),
            keyring_loaded_at: keys.loaded_at,
            control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
            in_force_cache: Arc::new(std::sync::Mutex::new(Vec::new())),
            classification_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            signature_lock: Arc::new(std::sync::Mutex::new(())),
            keyring_write_lock: Arc::new(std::sync::Mutex::new(())),
            v2_signers_lock: Arc::new(std::sync::Mutex::new(())),
            secret_publication_lock: Arc::new(std::sync::Mutex::new(())),
            execution_hold: None,
            audit_archive: None,
            audit_ceiling: Arc::new(crate::audit_ceiling::AuditCeiling::from_env()),
            allowances: Arc::new(crate::allowances::Allowances::from_env()),
            budget_book: Arc::default(),
            executions: Arc::default(),
            oauth_refresh_slots: Arc::default(),
            oauth_pending_rotations: Arc::default(),
            credential_revisions: Arc::default(),
            memory: crate::memory::MemoryBudget::from_env(),
            execution_slots: Arc::default(),
            pmconn_revocation: Arc::default(),
        }
    }

    /// Build the service with an explicit command runner (e.g. a
    /// [`connectors::RealCommandRunner`] in a deployment that is allowed to drive the real
    /// CLI). The HTTP client and store are supplied as usual.
    pub fn with_command_runner(
        store: Arc<dyn Store>,
        http: Arc<dyn HttpClient>,
        command: Arc<dyn CommandRunner>,
    ) -> Self {
        let backend: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), vault_passphrase().to_vec()));
        let keys = Self::build_approver_keyring_or_abort(&store);
        let announcer = Arc::new(crate::announce::Announcer::from_env());
        let push = Self::restored_push_registry(&store, !announcer.is_configured());
        let (paused, require_agent_approval) = Self::restored_switches(&store);
        EnforcementService {
            store,
            http,
            command,
            ssh: Arc::new(MockSshRunner::new()),
            push,
            announcer,
            backend,
            paused: Arc::new(AtomicBool::new(paused)),
            agents_paused: Arc::new(AtomicBool::new(false)),
            require_agent_approval: Arc::new(AtomicU8::new(require_agent_approval)),
            accept_v1_device_signatures: Arc::new(AtomicBool::new(false)),
            require_display_bound_approvals: Arc::new(AtomicBool::new(true)),
            oauth: None,
            approver_keyring: keys.keyring,
            approval_floor: keys.floor,
            keyring_persistence: keys.persistence,
            hosted: crate::hosted_from_env(),
            keyring_loaded_at: keys.loaded_at,
            control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
            in_force_cache: Arc::new(std::sync::Mutex::new(Vec::new())),
            classification_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            signature_lock: Arc::new(std::sync::Mutex::new(())),
            keyring_write_lock: Arc::new(std::sync::Mutex::new(())),
            v2_signers_lock: Arc::new(std::sync::Mutex::new(())),
            secret_publication_lock: Arc::new(std::sync::Mutex::new(())),
            execution_hold: None,
            audit_archive: None,
            audit_ceiling: Arc::new(crate::audit_ceiling::AuditCeiling::from_env()),
            allowances: Arc::new(crate::allowances::Allowances::from_env()),
            budget_book: Arc::default(),
            executions: Arc::default(),
            oauth_refresh_slots: Arc::default(),
            oauth_pending_rotations: Arc::default(),
            credential_revisions: Arc::default(),
            memory: crate::memory::MemoryBudget::from_env(),
            execution_slots: Arc::default(),
            pmconn_revocation: Arc::default(),
        }
    }

    /// Build the service from all of its components, the seam external secret backends (Infisical
    /// / KMS) plug into. The store, HTTP client, command runner, and [`SecretBackend`] are all
    /// supplied, so a worker can resolve some secrets from an external vault and the rest locally
    /// without the enforcement loop changing.
    pub fn from_components(
        store: Arc<dyn Store>,
        http: Arc<dyn HttpClient>,
        command: Arc<dyn CommandRunner>,
        backend: Arc<dyn SecretBackend>,
        oauth: Option<Arc<crate::oauth::OAuthRs>>,
    ) -> Self {
        let keys = Self::build_approver_keyring_or_abort(&store);
        let announcer = Arc::new(crate::announce::Announcer::from_env());
        let push = Self::restored_push_registry(&store, !announcer.is_configured());
        let (paused, require_agent_approval) = Self::restored_switches(&store);
        EnforcementService {
            store,
            http,
            command,
            ssh: Arc::new(MockSshRunner::new()),
            push,
            announcer,
            backend,
            paused: Arc::new(AtomicBool::new(paused)),
            agents_paused: Arc::new(AtomicBool::new(false)),
            require_agent_approval: Arc::new(AtomicU8::new(require_agent_approval)),
            accept_v1_device_signatures: Arc::new(AtomicBool::new(false)),
            require_display_bound_approvals: Arc::new(AtomicBool::new(true)),
            oauth,
            approver_keyring: keys.keyring,
            approval_floor: keys.floor,
            keyring_persistence: keys.persistence,
            hosted: crate::hosted_from_env(),
            keyring_loaded_at: keys.loaded_at,
            control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
            in_force_cache: Arc::new(std::sync::Mutex::new(Vec::new())),
            classification_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            signature_lock: Arc::new(std::sync::Mutex::new(())),
            keyring_write_lock: Arc::new(std::sync::Mutex::new(())),
            v2_signers_lock: Arc::new(std::sync::Mutex::new(())),
            secret_publication_lock: Arc::new(std::sync::Mutex::new(())),
            execution_hold: None,
            audit_archive: None,
            audit_ceiling: Arc::new(crate::audit_ceiling::AuditCeiling::from_env()),
            allowances: Arc::new(crate::allowances::Allowances::from_env()),
            budget_book: Arc::default(),
            executions: Arc::default(),
            oauth_refresh_slots: Arc::default(),
            oauth_pending_rotations: Arc::default(),
            credential_revisions: Arc::default(),
            memory: crate::memory::MemoryBudget::from_env(),
            execution_slots: Arc::default(),
            pmconn_revocation: Arc::default(),
        }
    }

    /// Attach the per-tenant execution hold. Consuming builder so it composes with all three
    /// constructors without widening any of them; the default is no hold at all.
    pub fn with_execution_hold(mut self, hold: Arc<crate::restore::ExecutionHold>) -> Self {
        self.execution_hold = Some(hold);
        self
    }

    /// The execution hold, for `/health` and for a test that wants to read it back.
    pub fn execution_hold(&self) -> Option<&Arc<crate::restore::ExecutionHold>> {
        self.execution_hold.as_ref()
    }

    /// Attach a hot-audit ceiling other than the one the environment resolves to.
    ///
    /// Consuming builder for the same reason [`Self::with_execution_hold`] is one, and it is how a
    /// test sets a low ceiling: the environment is process-wide and the suite runs in parallel, so
    /// one test's threshold set through `PERMAURA_AUDIT_HOT_CEILING` would be every other test's.
    /// Attach the archive writer. Absent means the flag is off or no bucket is configured, and then
    /// nothing is ever published or pruned.
    pub fn with_audit_archive(mut self, archive: Arc<crate::archive::AuditArchive>) -> Self {
        self.audit_archive = Some(archive);
        self
    }

    /// The archive writer, for `/health` and for the operator routes that walk the archive.
    pub fn audit_archive(&self) -> Option<&Arc<crate::archive::AuditArchive>> {
        self.audit_archive.as_ref()
    }

    pub fn with_audit_ceiling(mut self, ceiling: Arc<crate::audit_ceiling::AuditCeiling>) -> Self {
        self.audit_ceiling = ceiling;
        self
    }

    /// Use `memory` as this gateway's JSON memory and hold budgets rather than the environment's: how a test reaches a bound without the traffic, and how the binary shares one pool between the service and its HTTP client.
    pub fn with_memory_budget(mut self, memory: crate::memory::MemoryBudget) -> Self {
        self.memory = memory;
        self
    }

    /// Take the slot an approved held call needs from `limits`' execution slots, the ones the router admits every agent call under. Shared by every clone.
    pub fn attach_execution_slots(&self, limits: Arc<crate::limits::Limits>) {
        *self.execution_slots.write().unwrap_or_else(|e| e.into_inner()) = Some(limits);
    }

    /// Check every connector against `revocation` from now on. Shared by every clone.
    pub fn attach_revocation(&self, revocation: Arc<crate::manifest::Revocation>) {
        *self.pmconn_revocation.write().unwrap_or_else(|e| e.into_inner()) = revocation;
    }

    /// Why the manifest installed under `connector` may not be used, or `None` when nothing installed under that id is revoked. Each call is judged by [`Self::connection_revocation`].
    pub fn connector_revocation(&self, connector: &str) -> Result<Option<String>, GatewayError> {
        let revocation = self.pmconn_revocation.read().unwrap_or_else(|e| e.into_inner()).clone();
        Ok(self.store.get_connector_manifest(connector)?.and_then(|m| revocation.refuses_installed(&m)))
    }

    /// Why `connection` may not run because what it was made from is revoked, or `None`.
    ///
    /// Judged by the catalog entry its capabilities were copied from: one made from the built-in preset is never refused for a manifest that later replaced it, and one made from a revoked manifest stays refused after that manifest is removed or replaced. A connection that records no origin is judged by whatever is installed under its connector id, which fails closed.
    pub fn connection_revocation(&self, connection: &permaura_core::Connection) -> Result<Option<String>, GatewayError> {
        match &connection.made_from {
            Some(permaura_core::CatalogOrigin::BuiltIn | permaura_core::CatalogOrigin::Discovered) => Ok(None),
            Some(permaura_core::CatalogOrigin::Installed { version, key_id }) => {
                let revocation = self.pmconn_revocation.read().unwrap_or_else(|e| e.into_inner()).clone();
                Ok(revocation.refuses_origin(&connection.connector, *version, key_id.as_deref()))
            }
            None => self.connector_revocation(&connection.connector),
        }
    }

    /// The execution slot an approved held call whose params are `params` runs under, if it needs one, taken before the claim. As on 1.3.52 it needs none: it reserves a slot's share of byte buffers in the pool beside its params ([`crate::memory::MemoryBudget::parse_held`]), so agent calls filling the slots never refuse an approve and an approve never takes a slot from them. Only one whose params and that share could never fit the pool together takes a slot from the ones the router admits every agent call under, waiting as a queued call does unless `at_once`; when they are all busy that is the 429 an agent call gets, and the approval stays pending for the approver to try again. `None` also on a service no router admits calls for.
    async fn approved_call_slot(&self, params: &JsonText, at_once: bool) -> Result<Option<crate::limits::ExecutionSlot>, GatewayError> {
        if self.memory.held_fits_beside_buffers(params.get().as_bytes()) {
            return Ok(None);
        }
        let limits = self.execution_slots.read().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(limits) = limits else { return Ok(None) };
        match limits.admit_approved(at_once).await {
            Ok(slot) => Ok(Some(slot)),
            Err(reason) => Err(reason.into_error(limits.retry_after_secs(reason))),
        }
    }

    /// The JSON memory and hold budgets.
    pub fn memory(&self) -> &crate::memory::MemoryBudget {
        &self.memory
    }

    /// The hot-audit ceiling, for `/health` and for a test that wants to read it back.
    pub fn audit_ceiling(&self) -> &Arc<crate::audit_ceiling::AuditCeiling> {
        &self.audit_ceiling
    }

    /// Replace the plan allowances. Taken as a builder for the reason
    /// [`Self::with_audit_ceiling`] is: the four variables are process-wide and the suite runs in
    /// parallel, so a test that set one would set it for every other test in the binary.
    pub fn with_allowances(mut self, allowances: Arc<crate::allowances::Allowances>) -> Self {
        self.allowances = allowances;
        self
    }

    /// The plan allowances, for `/health` and for a test that wants to read them back.
    pub fn allowances(&self) -> &Arc<crate::allowances::Allowances> {
        &self.allowances
    }

    /// How many live rows of `allowance` this gateway holds.
    ///
    /// **Live** means present in the store right now. Every one of the four is hard-deleted rather
    /// than tombstoned, so a row that is gone frees its slot immediately and there is no soft-delete
    /// state to exclude. Two rows are excluded anyway, and both for the same reason: they are not
    /// rows the customer created and neither can be removed, so counting them would quietly charge a
    /// plan of N for N-1.
    ///
    /// - the `operator` agent, minted by [`crate::seed::clean_bootstrap`] as this gateway's own
    ///   identity rather than as an agent anybody enrolled;
    /// - the Default baseline grant, which [`crate::seed::ensure_default_grant`] guarantees exists
    ///   and which the delete route refuses to remove while it is the default.
    ///
    /// A pending agent DOES count. It occupies a row, it is one click from approved, and a ceiling
    /// that ignored pending agents could be walked straight past by an enrolment loop.
    pub fn allowance_count(
        &self,
        allowance: crate::allowances::Allowance,
    ) -> Result<u64, GatewayError> {
        use crate::allowances::Allowance;
        let n = match allowance {
            Allowance::Agents => self
                .store
                .list_agents()?
                .iter()
                .filter(|a| a.id != crate::seed::OPERATOR_AGENT_ID)
                .count(),
            // A staged row is parked bytes a pending hold names, not a secret anyone created; the pending ceiling bounds them.
            Allowance::Secrets => self
                .store
                .list_secret_ids()?
                .iter()
                .filter(|id| !crate::secret_inventory::is_staging_secret_id(id))
                .count(),
            Allowance::Grants => self
                .store
                .list_grants()?
                .iter()
                .filter(|g| !g.is_default)
                .count(),
            Allowance::Connections => self.store.list_connections()?.len(),
        };
        Ok(n as u64)
    }

    /// Refuse a new row of `allowance` when this gateway is at its plan ceiling.
    ///
    /// Called in the service layer immediately before the store write it guards, so a refusal has
    /// created nothing. The count is a store read; nothing here writes until the refusal is decided,
    /// at which point one audited denial is appended. That append is a snapshot upload on a hosted
    /// worker, and it is the right trade: it is exactly the cost of the create it refused, it is the
    /// only record an operator has that the ceiling is biting, and three of the four creates are
    /// operator-authenticated rather than agent-drivable. An append that fails does not rescue the
    /// request: the refusal stands and the failure is logged, because the alternative is letting a
    /// tenant past its ceiling whenever the store is unwell.
    pub fn refuse_if_over_allowance(
        &self,
        allowance: crate::allowances::Allowance,
        session: Option<&Session>,
    ) -> Result<(), GatewayError> {
        let refusal = self.refuse_if_over_allowance_unrecorded(allowance);
        if let Err(e) = &refusal {
            self.record_allowance_refusal(allowance, e, session);
        }
        refusal
    }

    /// [`Self::refuse_if_over_allowance`] without its audit record, for a check made inside a store unit of work, where the chain append cannot run; the caller records the refusal after the unit with [`Self::record_allowance_refusal`].
    pub(crate) fn refuse_if_over_allowance_unrecorded(
        &self,
        allowance: crate::allowances::Allowance,
    ) -> Result<(), GatewayError> {
        if self.allowances.config().limit(allowance).is_none() {
            return Ok(());
        }
        let current = self.allowance_count(allowance)?;
        self.allowances.admit(allowance, current)
    }

    /// Append the audited denial for `refusal` when it is an allowance refusal; any other error records nothing.
    pub(crate) fn record_allowance_refusal(
        &self,
        allowance: crate::allowances::Allowance,
        refusal: &GatewayError,
        session: Option<&Session>,
    ) {
        let GatewayError::AllowanceExceeded { current, limit, .. } = refusal else { return };
        let (current, limit) = (*current, *limit);
        let mut payload = AuditPayload::new(
            crate::allowances::AUDIT_ACTION,
            crate::allowances::AUDIT_RESOURCE,
            "deny",
        );
        payload.agent_id = session.map(|s| s.agent_id.clone());
        payload.session_id = session.map(|s| s.id.clone());
        payload.user_id = session.and_then(|s| s.user_id.clone());
        payload.summary = serde_json::json!({
            "allowance": allowance.as_str(),
            "current": current,
            "limit": limit,
        });
        if let Err(e) = self.store.append_audit(payload) {
            tracing::error!(
                allowance = allowance.as_str(),
                error = %e,
                "could not record an allowance denial; the create is still refused"
            );
        }
    }

    /// Write a secret row, charging it to the Secrets allowance when it adds one, and say whether it replaced a row.
    ///
    /// The slot is read and the allowance counted again under [`Self::lock_secret_publication`], inside the unit that writes, so two writes that both saw the last free slot before waiting on another lock cannot both take it. A replacement is never charged, so a rotation at the ceiling still lands.
    ///
    /// Nothing is written unless `check` passes, asked inside the same unit and under the same lock, so nothing it read can change before the row lands.
    pub(crate) fn publish_secret(
        &self,
        record: permaura_core::SecretRecord,
        session: Option<&Session>,
        check: impl FnOnce(&dyn Store) -> Result<(), GatewayError>,
    ) -> Result<bool, GatewayError> {
        let published = self.store.transaction(|store| {
            let _publish = self.lock_secret_publication();
            check(store)?;
            let replaced = self.store.get_secret(&record.id)?.is_some();
            if !replaced {
                self.refuse_if_over_allowance_unrecorded(crate::allowances::Allowance::Secrets)?;
            }
            let id = record.id.clone();
            self.store.put_secret(record)?;
            self.note_credential_change(&id);
            Ok(replaced)
        });
        if let Err(e) = &published {
            self.record_allowance_refusal(crate::allowances::Allowance::Secrets, e, session);
        }
        published
    }

    /// Watch `secret_id` for deliberate credential changes from now on, for a connector OAuth dance that will write it.
    pub fn watch_credential(&self, secret_id: &str) -> crate::oauth_connect::CredentialWatch {
        self.credential_revisions.watch(secret_id)
    }

    /// Watch `connection_id` for its removal from now on, for a connector OAuth dance that will write its credential.
    pub fn watch_connection_removal(&self, connection_id: &str) -> crate::oauth_connect::CredentialWatch {
        self.credential_revisions.watch_removal(connection_id)
    }

    /// Note that `connection_id` was removed. Every OAuth dance outstanding against it is stale from here on, even once a connection with the same id, stamp and slot is imported again.
    pub fn note_connection_removed(&self, connection_id: &str) {
        self.credential_revisions.note_removal(connection_id);
    }

    /// Note a deliberate change to the credential in `secret_id`: a write or a delete, including the delete a connection's removal makes when nothing else uses the slot. Every OAuth dance outstanding against it is stale from here on. A refresh rotation is not one.
    pub fn note_credential_change(&self, secret_id: &str) {
        self.credential_revisions.note_change(secret_id);
    }

    /// The lock every write that adds a secret row holds from its Secrets allowance count to its insert. Take it only inside a store unit of work, after the store's own serialization, as [`Self::locked_store_section`] orders its locks.
    pub(crate) fn lock_secret_publication(&self) -> std::sync::MutexGuard<'_, ()> {
        crate::store::bridge::lock_donating(&self.secret_publication_lock).unwrap_or_else(|p| p.into_inner())
    }

    /// How many events the hot store holds, and what this gateway is not currently able to do well.
    ///
    /// One string, joining the store's own durability note with the audit-pressure note, because a
    /// console that shows one and hides the other is showing half the answer, and a hot store at
    /// its ceiling is a condition of the store, which is what the field a console already reads is
    /// called.
    pub fn degraded(&self) -> Option<String> {
        let store = self.store.degraded();
        // A store that cannot answer how long its chain is has larger problems, and every one of
        // them is already reported by the line above. Silence beats inventing a band.
        let pressure = self
            .store
            .audit_len()
            .ok()
            .and_then(|events| self.audit_ceiling.degraded_note(events));
        match (store, pressure) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        }
    }

    /// Refuse a NEW execution when the hot audit store is at its ceiling, and signal the operator
    /// from the warning band below it.
    ///
    /// Called at the fence, immediately before the pre-execution `"attempt"` append and below
    /// [`Self::refuse_if_held`], which is what makes a refusal here append nothing and mutate
    /// nothing. It gates the decision to execute and never the recording of one: everything after
    /// the fence, including the terminal event of an execution already running, is appended at any
    /// pressure. See [`crate::audit_ceiling`].
    pub fn refuse_if_audit_full(&self) -> Result<(), GatewayError> {
        let events = self.store.audit_len()?;
        // Kicked before the ceiling decides, not after. A tenant that has already reached the
        // ceiling is exactly the one whose archive has to keep running, and a refusal that also
        // stopped the only thing able to bring the count down would be a refusal nothing ends.
        // The kick spawns and returns; this call never waits on a pass.
        if let Some(archive) = &self.audit_archive {
            let pressure = self.audit_ceiling.band(events) != crate::audit_ceiling::Band::Normal;
            archive.kick(self.store.clone(), events, pressure);
        }
        self.audit_ceiling.admit(events)
    }

    /// Refuse this caller when the tenant is held, and let it through when it is not.
    ///
    /// The **only** entry point to the hold, and it is called from exactly four places: the two
    /// service methods below, the vault export route and [`Self::send_with_credential`]. Placing it here rather than in route
    /// middleware is what makes a new execution route unable to miss it, and it is also what keeps
    /// the layer-2 recheck off every read path: this is the one thing that triggers a read, so an
    /// idle instance costs nothing and still scales to zero.
    pub fn refuse_if_held(&self) -> Result<(), GatewayError> {
        match &self.execution_hold {
            Some(hold) => hold.refuse_if_held(),
            None => Ok(()),
        }
    }

    /// The reconciliation this gateway is in, or `None` when it has never been restored.
    ///
    /// Read from the store rather than cached, and that is deliberate. A hosted worker is several
    /// Cloud Run instances, and the cached alternative fails in the wrong direction: an instance
    /// whose cache predates the restore would hold an empty list and let every restored grant,
    /// device and connection act the moment the hold was lifted. It is one indexed row read on a
    /// path that already reads a capability, a connection, an agent and a secret.
    ///
    /// An unreadable record is an error rather than `None`: see [`crate::reconcile::load`].
    pub fn reconciliation(&self) -> Result<Option<crate::reconcile::ReconciliationRecord>, GatewayError> {
        crate::reconcile::load(self.store.as_ref())
    }

    /// Refuse restored authority that its owner has not confirmed (the restore's review list).
    ///
    /// **Beside [`Self::refuse_if_held`] rather than inside it**, because the two outlive each other
    /// in opposite directions: the hold is cleared by the restoration authority as soon as the list
    /// is closed, and this keeps binding for as long as an item is unreviewed. A device, grant,
    /// connection, secret or agent that came back with a promoted snapshot cannot act on the
    /// strength of having been trusted by a generation that was thrown away.
    ///
    /// Takes the record rather than reading it, so one invocation asks the store once and checks
    /// every kind it touches against the same answer.
    pub fn refuse_if_unreviewed(
        review: Option<&crate::reconcile::ReconciliationRecord>,
        kind: crate::reconcile::ReviewKind,
        id: &str,
    ) -> Option<String> {
        review.filter(|r| r.blocks(kind, id)).map(|_| {
            format!(
                "The {} '{id}' came back with a restored snapshot and its owner has not confirmed it yet. Denied.",
                kind.as_str()
            )
        })
    }

    /// Swap in a real SSH transport (e.g. a `RealSshRunner` behind the `ssh-transport` feature) for
    /// [`CapabilityKind::Ssh`] capabilities. Consuming builder so it composes with the constructors
    /// without widening their signatures; the default is a [`connectors::MockSshRunner`].
    pub fn with_ssh_runner(mut self, ssh: Arc<dyn SshRunner>) -> Self {
        self.ssh = ssh;
        self
    }

    /// Borrow the underlying store (used by the REST/MCP layers for plain reads/writes).
    /// The HTTP client, for callers that must make a gateway-side call outside the connector path
    /// (the OAuth token exchange). Shared so tests drive it with the same mock.
    pub fn http(&self) -> &Arc<dyn HttpClient> {
        &self.http
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The executions this process is running, and whether it still admits new ones.
    pub fn executions(&self) -> &Arc<crate::drain::Executions> {
        &self.executions
    }

    /// Stop admitting executions, for a gateway that is shutting down. Returns how many were running.
    pub fn begin_drain(&self) -> usize {
        self.executions.begin_drain()
    }

    /// Borrow the custody seam. The invoke loop resolves through it for one upstream call; the vault
    /// export path is the only other caller, and it is the reason a bundle is custody-agnostic:
    /// local-vault, Infisical and KMS secrets all arrive as plaintext through this one method.
    pub fn backend(&self) -> &Arc<dyn SecretBackend> {
        &self.backend
    }

    /// Whether the operator kill switch is engaged (every agent invoke denied).
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Engage/release the operator kill switch, recorded in the store so a restart keeps it.
    pub fn set_paused(&self, paused: bool) -> Result<(), GatewayError> {
        self.set_switch(&self.paused, BROKER_PAUSED_META, paused)
    }

    /// Whether the deployment has paused every agent ([`Self::agents_paused`] doc on the field).
    pub fn agents_paused(&self) -> bool {
        self.agents_paused.load(Ordering::SeqCst)
    }

    /// Pause every agent for the life of this process, as `PERMAURA_AGENTS_PAUSED` does at boot.
    pub fn pause_agents_for_this_run(&self) {
        self.agents_paused.store(true, Ordering::SeqCst);
    }

    /// At start, hold agent sessions' clocks still across a deployment pause: a paused run records when the pause began, and the first run without it moves every agent session that was live then forward by the paused span, so an agent nobody could use through a lapse's grace or a decommission comes back with the time it had left. Returns how many sessions it moved.
    pub fn settle_agent_session_clock_at_start(&self) -> Result<u64, GatewayError> {
        let key = crate::store::AGENTS_PAUSED_SINCE_META;
        let paused = self.agents_paused();
        self.store.transaction(|store| {
            let since = crate::store::agents_paused_since(store)?;
            let now = now_ms();
            if paused {
                if since.is_none() {
                    store.put_meta(key, &now.to_string())?;
                }
                return Ok(0);
            }
            let Some(since) = since else { return Ok(0) };
            let span = (now - since).max(0);
            let mut moved = 0;
            for mut session in store.list_sessions()? {
                if session.role != SessionRole::Agent || session.revoked {
                    continue;
                }
                // A row from before the cap carries no expiry; it gets the one a touch at its last use would have given it.
                let expiry = session.expires_at.unwrap_or_else(|| {
                    session.last_used_at.unwrap_or(session.created_at) + crate::store::AGENT_SESSION_TTL_MS
                });
                if expiry <= since {
                    continue;
                }
                session.expires_at = Some(expiry + span);
                store.put_session(session)?;
                moved += 1;
            }
            store.put_meta(key, "")?;
            Ok(moved)
        })
    }

    /// Refuse minting or redeeming an enrolment code while the deployment has paused agents. Reads and writes nothing.
    pub fn refuse_enrolment_if_agents_paused(&self) -> Result<(), GatewayError> {
        if self.agents_paused() {
            return Err(GatewayError::Denied(AGENTS_PAUSED_ENROLMENT_MESSAGE.into()));
        }
        Ok(())
    }

    /// Refuse an agent, or any execution, while the deployment has paused agents. Reads and writes nothing.
    pub fn refuse_if_agents_paused(&self) -> Result<(), GatewayError> {
        if self.agents_paused() {
            return Err(GatewayError::Denied(AGENTS_PAUSED_MESSAGE.into()));
        }
        Ok(())
    }

    /// Whether a newly-seen OAuth agent must be approved by an operator before it can invoke.
    pub fn require_agent_approval(&self) -> bool {
        match self.require_agent_approval.load(Ordering::SeqCst) {
            AGENT_GATE_UNSET => self.agent_gate_default(),
            AGENT_GATE_STORED_OFF => false,
            _ => true,
        }
    }

    /// Whether [`Self::require_agent_approval`] is the default, the operator's stored choice, or the environment's.
    pub fn require_agent_approval_source(&self) -> AgentGateSource {
        match self.require_agent_approval.load(Ordering::SeqCst) {
            AGENT_GATE_UNSET => AgentGateSource::Default,
            AGENT_GATE_THIS_RUN => AgentGateSource::Environment,
            _ => AgentGateSource::Stored,
        }
    }

    /// The new-agent gate while nothing is stored: on once a device is trusted on a gateway reachable from off the host, a hosted worker or one with a public URL, where approving an agent from off the host is already held for that device. Off with no device, and on a gateway no OAuth client can reach.
    pub fn agent_gate_default(&self) -> bool {
        self.reachable_from_off_host() && self.any_device_trusted()
    }

    fn reachable_from_off_host(&self) -> bool {
        self.hosted || self.oauth.is_some()
    }

    /// Turn the new-agent approval gate on/off. Affects only agents seen *after* the change: an
    /// already-approved agent stays approved, and a Pending one stays Pending until approved.
    /// Recorded in the store so a restart keeps it, and from then on it wins over the default.
    ///
    /// The same order as [`Self::set_switch`]: engaging applies before the write, releasing once the row says so. A `false` written on a reachable gateway with no device trusted is marked unanchored; see [`Self::clear_unanchored_agent_gate_off`].
    pub fn set_require_agent_approval(&self, require: bool) -> Result<(), GatewayError> {
        let state = if require { AGENT_GATE_STORED_ON } else { AGENT_GATE_STORED_OFF };
        let unanchored = !require && self.reachable_from_off_host() && !self.any_device_trusted();
        if require {
            self.require_agent_approval.store(state, Ordering::SeqCst);
        }
        self.store.transaction(|store| {
            store.put_meta(BROKER_REQUIRE_AGENT_APPROVAL_META, if require { "true" } else { "false" })?;
            store.put_meta(BROKER_REQUIRE_AGENT_APPROVAL_UNANCHORED_META, if unanchored { "1" } else { "" })?;
            self.require_agent_approval.store(state, Ordering::SeqCst);
            Ok(())
        })
    }

    /// At the first device trusted on a reachable gateway, return a stored `false` that no device holder confirmed to the default, which is now on. Before any device a remote write is not held and a loopback one may be a same-user agent, so inheriting it would leave the gate off from this pairing on with nothing to say so (the rule the approval floor follows). Returns whether it cleared one.
    pub fn clear_unanchored_agent_gate_off(&self) -> Result<bool, GatewayError> {
        if !self.reachable_from_off_host()
            || self.store.get_meta(BROKER_REQUIRE_AGENT_APPROVAL_META)?.as_deref() != Some("false")
            || self.store.get_meta(BROKER_REQUIRE_AGENT_APPROVAL_UNANCHORED_META)?.as_deref() != Some("1")
        {
            return Ok(false);
        }
        self.store.transaction(|store| {
            store.put_meta(BROKER_REQUIRE_AGENT_APPROVAL_META, "")?;
            store.put_meta(BROKER_REQUIRE_AGENT_APPROVAL_UNANCHORED_META, "")?;
            let _ = self.require_agent_approval.compare_exchange(
                AGENT_GATE_STORED_OFF,
                AGENT_GATE_UNSET,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
            Ok(())
        })?;
        Ok(true)
    }

    /// Engage the new-agent gate for this run without recording it, for `PERMAURA_REQUIRE_AGENT_APPROVAL` at boot: a deployment that stops setting the variable must not keep a gate nobody asked the store for.
    pub fn require_agent_approval_for_this_run(&self) {
        self.require_agent_approval.store(AGENT_GATE_THIS_RUN, Ordering::SeqCst);
    }

    /// Engage or release one broker switch and record it.
    ///
    /// Engaging applies in this process before the write, because a kill switch that waits for storage is not one; a failed write is still returned, since a restart would lift a switch that was never saved. Releasing applies only once the row says so. The flag is set again inside the unit so two overlapping toggles leave memory and the row agreeing.
    fn set_switch(&self, flag: &AtomicBool, key: &str, on: bool) -> Result<(), GatewayError> {
        if on {
            flag.store(true, Ordering::SeqCst);
        }
        self.store.transaction(|store| {
            store.put_meta(key, if on { "true" } else { "false" })?;
            flag.store(on, Ordering::SeqCst);
            Ok(())
        })
    }

    /// The broker switches as the store last recorded them. An unreadable row engages its switch: lifting either is what a remote resume holds for a device signature, and reading "off" from a failure would grant that with none. The gate's row may be absent or cleared, which leaves it to its default, and only an explicit `false` turns it off.
    fn restored_switches(store: &Arc<dyn Store>) -> (bool, u8) {
        let read = |key: &str| {
            store.get_meta(key).unwrap_or_else(|e| {
                tracing::error!(error = %e, key, "could not read a broker switch at start; engaging it");
                Some("true".into())
            })
        };
        let gate = match read(BROKER_REQUIRE_AGENT_APPROVAL_META).as_deref() {
            None | Some("") => AGENT_GATE_UNSET,
            Some("false") => AGENT_GATE_STORED_OFF,
            Some(_) => AGENT_GATE_STORED_ON,
        };
        (read(BROKER_PAUSED_META).as_deref() == Some("true"), gate)
    }

    /// Accept or refuse device signatures that name no gateway (the v1 preimages). Seeded from
    /// `PERMAURA_ACCEPT_V1_DEVICE_SIGNATURES` at boot.
    pub fn set_accept_v1_device_signatures(&self, accept: bool) {
        self.accept_v1_device_signatures.store(accept, Ordering::SeqCst);
    }

    /// Whether a v1 device signature can be accepted at all here. Even when this is true, an approver
    /// that has signed v2 here before is held to v2.
    pub fn accepts_v1_device_signatures(&self) -> bool {
        self.accept_v1_device_signatures.load(Ordering::SeqCst)
    }

    /// Require (or stop requiring) that every device-signed approve binds what the approver was shown.
    /// Seeded from `PERMAURA_REQUIRE_DISPLAY_BOUND_APPROVALS` at boot.
    pub fn set_require_display_bound_approvals(&self, require: bool) {
        self.require_display_bound_approvals.store(require, Ordering::SeqCst);
    }

    /// Whether every device-signed approve here must be a v3 signature.
    pub fn requires_display_bound_approvals(&self) -> bool {
        self.require_display_bound_approvals.load(Ordering::SeqCst)
    }

    /// This gateway's approval audience, minted and stored the first time anything asks for it.
    ///
    /// Random rather than derived from a URL or a control-plane id, because a gateway does not always
    /// know either and must never change its value: a device pins it at pairing and refuses to sign
    /// for a gateway serving a different one.
    pub fn approval_audience(&self) -> Result<String, GatewayError> {
        let stored = |store: &Arc<dyn Store>| -> Result<Option<String>, GatewayError> {
            Ok(store.get_meta(APPROVAL_AUDIENCE_META)?.filter(|a| !a.trim().is_empty()))
        };
        if let Some(existing) = stored(&self.store)? {
            return Ok(existing);
        }
        use rand::RngCore as _;
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let minted = format!("aud_{}", raw.iter().map(|b| format!("{b:02x}")).collect::<String>());
        self.store.put_meta(APPROVAL_AUDIENCE_META, &minted)?;
        // Read back rather than trusting the write: two instances of one hosted worker can mint at the
        // same moment, and every instance has to serve the value the store kept.
        Ok(stored(&self.store)?.unwrap_or(minted))
    }

    /// The audience to serve beside an approval, a keyring listing or a pairing answer, or `None` when
    /// it cannot be produced. A response without it is what an older gateway sends, which every client
    /// already treats as "sign v1", so a failure here degrades a read instead of failing it.
    pub fn served_approval_audience(&self) -> Option<String> {
        match self.approval_audience() {
            Ok(audience) => Some(audience),
            Err(e) => {
                tracing::error!(error = %e, "this gateway could not read or mint its approval audience; serving none");
                None
            }
        }
    }

    fn v2_signers(&self) -> Result<std::collections::BTreeSet<String>, GatewayError> {
        self.signer_record(DEVICE_SIG_V2_APPROVERS_META, "v2")
    }

    fn display_signers(&self) -> Result<std::collections::BTreeSet<String>, GatewayError> {
        self.signer_record(DEVICE_SIG_DISPLAY_APPROVERS_META, "v3")
    }

    fn signer_record(&self, meta: &str, version: &str) -> Result<std::collections::BTreeSet<String>, GatewayError> {
        match self.store.get_meta(meta)? {
            Some(json) if !json.trim().is_empty() => serde_json::from_str(&json).map_err(|e| {
                GatewayError::Internal(format!("the record of approvers that sign {version} is not readable: {e}"))
            }),
            _ => Ok(std::collections::BTreeSet::new()),
        }
    }

    /// Remember that `approver` signed v2 here, so a v1 signature carrying its id is refused from now
    /// on. Written only the first time, so an ordinary approval costs no write.
    pub fn note_v2_signer(&self, approver: &str) {
        self.note_signer(DEVICE_SIG_V2_APPROVERS_META, "v2", approver);
    }

    /// Remember that `approver` signed v3 here, so an approval from it that does not bind the
    /// parameters it showed is refused from now on.
    pub fn note_display_signer(&self, approver: &str) {
        self.note_signer(DEVICE_SIG_DISPLAY_APPROVERS_META, "v3", approver);
    }

    /// Run `f` holding `lock` inside one store unit of work, so whatever `f` writes is uploaded after `lock` is released.
    ///
    /// Lock order, everywhere: [`Self::control_plane_lock`], then the store's own serialization (a SQLite store holds `serial` for the unit), then exactly one of [`Self::signature_lock`], [`Self::keyring_write_lock`] or [`Self::v2_signers_lock`], each taken only here. A `std::sync::Mutex` held across a hosted upload parked the next caller on it with the runtime worker the upload needed, and one taken before `serial` deadlocked against a holder of `serial`.
    fn locked_store_section<T>(
        &self,
        lock: &std::sync::Mutex<()>,
        f: impl FnOnce() -> Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        self.store.transaction(|_| {
            let _guard = crate::store::bridge::lock_donating(lock).unwrap_or_else(|p| p.into_inner());
            f()
        })
    }

    fn note_signer(&self, meta: &str, version: &str, approver: &str) {
        // Read first: a unit of work waits for any upload in flight, and an approver already on record needs no write.
        match self.signer_record(meta, version) {
            Ok(signers) if signers.contains(approver) => return,
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, approver, version, "could not read the approvers that sign this version; not recording this one");
                return;
            }
        }
        let noted = self.locked_store_section(&self.v2_signers_lock, || {
            let mut signers = self.signer_record(meta, version)?;
            if signers.insert(approver.to_string()) {
                let json = serde_json::to_string(&signers).unwrap_or_else(|_| "[]".into());
                self.store.put_meta(meta, &json)?;
            }
            Ok(())
        });
        if let Err(e) = noted {
            tracing::error!(error = %e, approver, version, "could not record that this approver signs this version");
        }
    }

    /// Why an approval must be refused because its signature does not bind the parameters the
    /// approver was shown, or `None`. Only an APPROVE is ever refused, because a denial runs nothing:
    /// always while [`Self::requires_display_bound_approvals`] is on, and otherwise from an approver
    /// that has signed v3 here, so an app that predates the rendering keeps working until its first
    /// v3 signature, the same terms the v1 to v2 move was made on.
    pub fn display_binding_refusal(&self, approver: &str, approve: bool, display_digest: Option<&str>) -> Option<String> {
        if display_digest.is_some() || !approve {
            return None;
        }
        if self.requires_display_bound_approvals() {
            return Some(
                "this gateway accepts only approvals that bind the parameters the approver was shown; update the approving app".into(),
            );
        }
        match self.display_signers() {
            Ok(signers) if signers.contains(approver) => Some(format!(
                "approver '{approver}' has signed with the call's parameters shown before, so an approval that does not bind them is refused; update the app"
            )),
            Ok(_) => None,
            Err(e) => Some(e.to_string()),
        }
    }

    /// Why a device signature must be refused for its VERSION, before the signature itself is checked,
    /// or `None` when it may go on to verification. Shared by the approval and the device-control
    /// paths so the two cannot disagree about which signatures this gateway takes.
    ///
    /// A v2 signature (`audience` present) must name this gateway's own audience. A v1 signature names
    /// no gateway, so it could have been collected by any gateway that trusts the same device key and
    /// replayed here; it is taken only while v1 is accepted, and never from an approver that has
    /// already signed v2 here.
    pub fn device_signature_version_refusal(&self, approver: &str, audience: Option<&str>) -> Option<String> {
        // An empty audience is what a device with no pin for this gateway sends in some builds, and it
        // names no gateway any more than an absent one does.
        match audience.filter(|a| !a.is_empty()) {
            Some(claimed) => match self.approval_audience() {
                Ok(own) if own == claimed => None,
                Ok(_) => Some(format!(
                    "this signature was made for a different gateway (audience '{claimed}'), not this one"
                )),
                Err(e) => Some(format!("this gateway cannot read its own approval audience: {e}")),
            },
            // Shown by the phone as its re-pair message, so it says what to do first.
            None if !self.accepts_v1_device_signatures() => Some(
                "this device must be paired with this gateway again: its signature names no gateway, and this gateway accepts only \
                 signatures bound to it. Update the approving app if it is out of date, then pair it again"
                    .into(),
            ),
            None => match self.v2_signers() {
                Ok(signers) if signers.contains(approver) => Some(format!(
                    "approver '{approver}' has signed for this gateway by its audience before, so a signature that names no gateway is refused; pair it again"
                )),
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            },
        }
    }

    /// Re-read the keyring and floor from the store when this instance's copy has aged past
    /// [`KEYRING_REFRESH_MS`]. A no-op on every backend except [`KeyringPersistence::Store`], because
    /// nothing else can be written behind this process's back.
    ///
    /// Called from each read of the trust state rather than on a timer so an idle instance does no
    /// work and a busy one is never more than one window behind whichever instance did the pairing.
    /// Age this instance's keyring snapshot past its TTL, so the next trust read has to go to the
    /// store. Stands in for wall-clock time passing on an instance that has not seen a sibling's write.
    #[cfg(test)]
    pub fn expire_keyring_cache_for_test(&self) {
        self.keyring_loaded_at
            .store(now_ms() - KEYRING_REFRESH_MS - 1, Ordering::SeqCst);
    }

    fn refresh_keyring_if_stale(&self) {
        if !matches!(self.keyring_persistence, KeyringPersistence::Store) {
            return;
        }
        let age = now_ms().saturating_sub(self.keyring_loaded_at.load(Ordering::SeqCst));
        if age < KEYRING_REFRESH_MS {
            return;
        }
        self.refresh_keyring_now();
    }

    /// Re-read the keyring and floor from the store immediately, ignoring the TTL. The pairing path
    /// calls this inside its critical section: enrolling the second device has to be decided against
    /// what the *store* holds, not against a snapshot up to [`KEYRING_REFRESH_MS`] old, or two
    /// instances could each believe theirs is the first device and each take the trust-on-first-use
    /// branch that is supposed to happen exactly once per worker.
    ///
    /// A failed read KEEPS the current keyring and warns. Last-known-good is strictly safer than
    /// empty: an empty keyring reports `ever_enrolled() == false`, which drops the approval floor to
    /// `Approve` and re-opens bearer-only resolution; a transient database blip must not be able to
    /// do that. The clock is stamped either way so an outage cannot turn every read into a query.
    ///
    /// A WRITER must not use this: swallowing the failure would leave it applying its delta to a
    /// snapshot it knows nothing about and then serialising that snapshot over the shared row. Writers
    /// go through [`Self::mutate_keyring`], which uses the fallible [`Self::reload_keyring`].
    pub fn refresh_keyring_now(&self) {
        if let Err(e) = self.reload_keyring() {
            tracing::warn!(error = %e, "could not re-read the approver keyring from the store; keeping the last known good copy");
        }
    }

    /// The fallible core of [`Self::refresh_keyring_now`]: re-read the keyring and floor from the
    /// store and install them, or report why it could not.
    ///
    /// The clock is stamped before the read rather than after it, so this is the ONLY place the
    /// staleness deadline moves. A write path that stamped it would push the deadline forward without
    /// this instance ever having seen what another instance wrote, and a caller writing more often
    /// than [`KEYRING_REFRESH_MS`] would pin itself to an indefinitely stale keyring.
    fn reload_keyring(&self) -> Result<(), GatewayError> {
        if !matches!(self.keyring_persistence, KeyringPersistence::Store) {
            return Ok(());
        }
        self.keyring_loaded_at.store(now_ms(), Ordering::SeqCst);
        let (mut keyring, floor) =
            Self::load_persisted_keyring(&self.keyring_persistence, &self.store)?;
        // Statically provisioned keys are merged at construction, so a refresh that skipped them
        // would silently untrust every `PERMAURA_APPROVER_KEYS` device five seconds after boot.
        if let Ok(env) = std::env::var("PERMAURA_APPROVER_KEYS") {
            keyring.merge_env_str(&env);
        }
        *self.approver_keyring.write().expect("approver keyring lock not poisoned") = keyring;
        // The store is authoritative for the floor too, so a clear or a raise made on another
        // instance lands here. An opt-down this instance holds only in memory (its write failed) is
        // reverted to the stored, stricter value, the safe direction.
        *self.approval_floor.write().expect("approval floor lock not poisoned") = floor;
        Ok(())
    }

    /// The ONE writer for the approver keyring: apply `delta` to a keyring re-read from the store and
    /// persist the result, all inside a single critical section. `delta` reports whether it actually
    /// changed anything (a no-op is not persisted) alongside whatever the caller wants back.
    ///
    /// **Why the read and the write must be in the same section.** The keyring is serialised WHOLE on
    /// every write, so a mutation applied to a stale snapshot does not merely lose its own change; it
    /// writes that stale snapshot over everything every other instance has done since. On a
    /// multi-instance hosted worker that is a silent fail-OPEN: instance B revoking a device from a
    /// five-second-old snapshot erases the pairing instance A just made, and if B's snapshot was empty
    /// the row is emptied outright, `ever_enrolled()` goes false, and [`Self::approval_floor`] drops
    /// from `DeviceSigned` back to `Approve`: bearer-only approval resolution re-opens on a tenant
    /// who believes it is closed. Refreshing *before* a blind write only narrows that window; the
    /// window is the bug, so the read and the write are one section.
    ///
    /// A failed re-read ABORTS the mutation rather than falling back to the in-memory copy. This is
    /// the one place where last-known-good is the wrong instinct: continuing would write a snapshot
    /// this instance knows to be unverified over the shared row, which is exactly the destruction
    /// above, so the caller gets an error it can retry instead.
    ///
    /// [`KeyringPersistence::File`] is deliberately left alone by the re-read (it is a no-op there):
    /// that disk belongs to one gateway process, nothing can write it behind this one's back, and
    /// re-reading it would let a keyring built from `PERMAURA_APPROVER_KEYS` and runtime pairings be
    /// reset by a file that never successfully saved.
    ///
    /// The lock is [`Self::keyring_write_lock`], not [`Self::control_plane_lock`]: the section is pure
    /// store access with no await in it, and revocation reaches here synchronously. The pairing path
    /// takes the control-plane mutex OUTSIDE this and this lock inside it, never the reverse, so the
    /// two orders cannot deadlock.
    ///
    /// The keyring lock is taken inside a store unit of work, after the store's own `serial`, because a held pairing or revocation resolved by a device signature arrives here inside `rest::apply_mutation`'s transaction already holding `serial`; a revocation that took the keyring lock first and `serial` second closed the cycle. See [`Self::locked_store_section`] for the order.
    fn mutate_keyring<T>(
        &self,
        delta: impl FnOnce(&mut ApproverKeyring) -> (bool, T),
    ) -> Result<T, GatewayError> {
        self.locked_store_section(&self.keyring_write_lock, || {
            self.reload_keyring()?;
            let (changed, out) = {
                let mut kr = self.approver_keyring.write().expect("approver keyring lock not poisoned");
                delta(&mut kr)
            };
            if changed {
                self.persist_keyring()?;
            }
            Ok(out)
        })
    }

    /// A point-in-time clone of the approver keyring, used by the relay loop so it can verify a
    /// signed approval without holding the keyring lock across the async resolve.
    pub fn approver_keyring_snapshot(&self) -> ApproverKeyring {
        self.refresh_keyring_if_stale();
        self.approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .clone()
    }

    /// Whether a usable (non-revoked) trusted signing key is enrolled for `approver_id`, the
    /// console's "trusted" signal, distinct from a merely-recorded enrolment pubkey.
    /// Refreshes first, like every other trust read. It did not, and on a store-backed keyring that
    /// is what made a hosted pairing look like it had not happened: the instance that performed the
    /// write reported the device trusted, and the next request (served by another Cloud Run instance,
    /// or by the same one holding a snapshot predating the write) reported it untrusted, because
    /// nothing on this path ever re-read the store. It is the value `GET /v1/devices` publishes as
    /// `is_trusted`, so that disagreement is what a person sees when they leave the screen and return.
    pub fn approver_key_trusted(&self, approver_id: &str) -> bool {
        self.refresh_keyring_if_stale();
        self.approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .trusted_key(approver_id)
            .is_some()
    }

    /// The pubkey a device's registry row recorded at enrolment. Nothing calls this: pairing verifies
    /// the possession proof carried in the pairing request itself, never this value.
    pub fn recorded_device_pubkey(&self, approver_id: &str) -> Option<String> {
        self.push.find_by_approver(approver_id).and_then(|d| d.approver_pubkey)
    }

    /// The key this worker actually TRUSTS for `approver_id`, read from the keyring rather than from
    /// the push registry.
    ///
    /// [`Self::recorded_device_pubkey`] answers a different question (what a device said its key was
    /// when it registered for notifications) and answers `None` for every approver that never
    /// registered. A revocation names the key it untrusted, and that key is this one; taking it from
    /// the registry instead means writing a fingerprint of nothing whenever there is no device row.
    pub fn trusted_approver_key(&self, approver_id: &str) -> Option<String> {
        self.refresh_keyring_if_stale();
        self.approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .trusted_key(approver_id)
            .map(str::to_string)
    }

    /// The whole trusted keyring, as `(approver_id, key_fp, revoked)`, freshly re-read from the store.
    ///
    /// The census behind `GET /v1/approver-keys`, and the answer to a keyring being enumerable only
    /// through the push-device registry it has no relationship with. The read is forced rather than
    /// TTL-bounded because this is what an owner consults before revoking: a stale snapshot could
    /// omit a key another Cloud Run instance paired minutes ago, and the one key missing from the
    /// list is the one that never gets revoked.
    ///
    /// Fingerprints, not public keys. A fingerprint is what the AS binds a pairing ticket to and what
    /// the audit chain records, so it is the identifier that actually joins the three surfaces up;
    /// the key material itself would add nothing a caller could act on.
    pub fn approver_key_census(&self) -> Vec<(String, String, bool)> {
        self.refresh_keyring_now();
        self.approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .entries()
            .into_iter()
            .map(|(id, pubkey, revoked)| (id.to_string(), key_fingerprint(pubkey), revoked))
            .collect()
    }

    /// The approver id a device signs as, so revoking the device can also untrust its signing key.
    pub fn device_approver(&self, device_id: &str) -> Option<String> {
        self.push.approver_for_device(device_id)
    }

    /// Trust an approver's device signing key (the pairing step) and report whether the keyring
    /// reached its durable home. A malformed key is `Ok(false)` and never stored.
    ///
    /// This is the variant the hosted pairing endpoint must use. There, a failed write is not a
    /// cosmetic problem: the store IS the keyring, so a pairing that did not persist is forgotten by
    /// the next refresh and by the next cold start, while the tenant has been told their phone is
    /// enrolled and believes approvals now require it. Telling the caller lets the endpoint answer
    /// with a failure they can retry instead of a success that quietly evaporates.
    pub fn trust_approver_key_durable(
        &self,
        approver_id: &str,
        pubkey_b64: &str,
    ) -> Result<bool, GatewayError> {
        self.trust_approver_key_for(approver_id, pubkey_b64, None)
    }

    /// [`Self::trust_approver_key_durable`], binding the key to the person it approves for (see
    /// [`crate::relay::approver::ApproverKeyring::add_for`]).
    ///
    /// Refused when the key is already trusted for a different person. Checked here, under the keyring
    /// write lock, because a held attribution is applied long after it was signed for, and another may
    /// have bound the key in the meantime.
    pub fn trust_approver_key_for(
        &self,
        approver_id: &str,
        pubkey_b64: &str,
        person: Option<&str>,
    ) -> Result<bool, GatewayError> {
        let applied = self.mutate_keyring(|kr| {
            if person.is_some_and(|asked| kr.bound_to_someone_else(approver_id, pubkey_b64, asked)) {
                return (false, None);
            }
            let added = kr.add_for(approver_id, pubkey_b64, person.map(str::to_string));
            (added, Some(added))
        })?;
        applied.ok_or_else(|| {
            GatewayError::Denied(
                "this device already approves for a different person; revoke it and pair it again to \
                 change whose approvals it counts as"
                    .into(),
            )
        })
    }

    /// [`Self::trust_approver_key_for`] for an enrolment that may retire the key `approver_id` holds now:
    /// only the key whose fingerprint is `replaces`, checked under the keyring write lock, because a held
    /// replacement is applied long after it was authorised against the key that was there then.
    pub fn trust_approver_key_replacing(
        &self,
        approver_id: &str,
        pubkey_b64: &str,
        person: Option<&str>,
        replaces: Option<&str>,
    ) -> Result<bool, GatewayError> {
        let applied = self.mutate_keyring(|kr| {
            let retires = kr.trusted_key(approver_id).filter(|k| *k != pubkey_b64).map(key_fingerprint);
            if retires.is_some() && retires.as_deref() != replaces {
                return (false, Some(Err(GatewayError::Denied(
                    "the key this approver id holds has changed since this pairing was asked for, so it no longer replaces the key it was approved to replace: pair the device again".into(),
                ))));
            }
            if person.is_some_and(|asked| kr.bound_to_someone_else(approver_id, pubkey_b64, asked)) {
                return (false, None);
            }
            let added = kr.add_for(approver_id, pubkey_b64, person.map(str::to_string));
            (added, Some(Ok(added)))
        })?;
        applied.unwrap_or_else(|| {
            Err(GatewayError::Denied(
                "this device already approves for a different person; revoke it and pair it again to \
                 change whose approvals it counts as"
                    .into(),
            ))
        })
    }

    /// How many distinct people have signed `approval` so far, counted exactly as its quorum is.
    pub fn people_signed(&self, approval: &PendingApproval) -> u8 {
        self.refresh_keyring_if_stale();
        let keyring = self.approver_keyring.read().expect("approver keyring lock not poisoned");
        live_people_count(&keyring, &approval.signatures)
    }

    /// Trust an approver's device signing key (the worker-local pairing step). MUST only be reached
    /// from a loopback path, never the broker; a bad key is rejected (`false`) and never stored.
    /// Persists to the selected backend (the store by default, or the `PERMAURA_APPROVER_KEYS_PATH`
    /// file) so the pairing survives a restart.
    ///
    /// Best-effort persistence, kept for the loopback callers that have always had it: `true` means
    /// the key is trusted in this process, not that it was written. On a self-run box those coincide
    /// closely enough. A caller that needs the distinction (anything running on a hosted worker)
    /// must use [`Self::trust_approver_key_durable`].
    pub fn trust_approver_key(&self, approver_id: &str, pubkey_b64: &str) -> bool {
        match self.trust_approver_key_durable(approver_id, pubkey_b64) {
            Ok(added) => added,
            Err(e) => {
                tracing::error!(approver = %approver_id, error = %e, "approver pairing did not persist; the key is trusted only in this process");
                // Not an unconditional `true`: [`Self::mutate_keyring`] aborts a write it could not
                // base on a fresh read, and that abort happens BEFORE the key is added, so the honest
                // answer is whatever the in-memory keyring actually holds now.
                self.approver_key_trusted(approver_id)
            }
        }
    }

    /// Revoke an approver's trusted signing key (a lost/rotated device). Fail-safe in what it does to
    /// the keyring (it only removes trust), so a remote caller may revoke with a step-up ticket.
    /// Pairing adds trust, so it is taken only from loopback on a self-run gateway and only on an
    /// owner step-up ticket on a hosted worker, and once a device is trusted every later pairing on
    /// either also waits for a trusted device's co-signature.
    ///
    /// The failure is REPORTED rather than logged, because this direction fails OPEN: a revocation
    /// that did not reach the store exists only in this process, so a restart (or, under
    /// [`KeyringPersistence::Store`], the next refresh within [`KEYRING_REFRESH_MS`]) brings the lost
    /// device's key back as trusted, while the operator has been told the device is revoked. Every
    /// caller must propagate it: answering 200 to a revocation that evaporates is the console telling
    /// someone their stolen phone can no longer approve when it can.
    ///
    /// A key `PERMAURA_APPROVER_KEYS` provisions is tombstoned as well, since the variable is merged again at every refresh and start.
    pub fn revoke_approver_key(&self, approver_id: &str) -> Result<(), GatewayError> {
        let provisioned = std::env::var("PERMAURA_APPROVER_KEYS").ok();
        self.mutate_keyring(|kr| (kr.revoke_provisioned(approver_id, provisioned.as_deref()), ()))
    }

    /// Whether the key `approver_id` is trusted with is one `PERMAURA_APPROVER_KEYS` provisions, so a revocation can say the variable still names it.
    pub fn approver_key_from_environment(&self, approver_id: &str) -> bool {
        let Ok(env) = std::env::var("PERMAURA_APPROVER_KEYS") else { return false };
        self.trusted_approver_key(approver_id)
            .is_some_and(|pk| ApproverKeyring::env_provisions(&env, approver_id, &pk))
    }

    /// Whether revoking `approver_id` would leave this worker with NO usable approver key at all.
    ///
    /// Revoking the last usable key is different in kind from every other revocation: while another
    /// usable device remains, the next enrolment is still held for that device to co-sign, and once
    /// none remains the anti-brick fallback re-opens the trust-on-first-use branch. That transition
    /// LOOSENS the trust root, which is why a self-run gateway demands recovery authority for it on top
    /// of any step-up (see `rest::guarded_revoke_approver_key`).
    ///
    /// Re-reads the store first: an instance deciding "another device is still usable" from a stale
    /// snapshot would wave through exactly the revocation that empties the keyring.
    pub fn revoking_would_empty_keyring(&self, approver_id: &str) -> bool {
        self.refresh_keyring_now();
        let mut keyring =
            self.approver_keyring.read().expect("approver keyring lock not poisoned").clone();
        if keyring.trusted_key(approver_id).is_none() {
            // Already unusable (unknown or revoked): revoking it changes nothing, so it can never be
            // the revocation that empties the keyring.
            return false;
        }
        keyring.revoke(approver_id);
        keyring.is_empty()
    }

    /// Write the keyring through to whichever backend this gateway selected. Callable only from
    /// [`Self::mutate_keyring`], which has just re-read the store under the write lock; a caller that
    /// reached here from anywhere else would be serialising a snapshot of unknown age over the shared
    /// row.
    fn persist_keyring(&self) -> Result<(), GatewayError> {
        match &self.keyring_persistence {
            KeyringPersistence::File { keys, .. } => {
                let kr = self.approver_keyring.read().expect("approver keyring lock not poisoned");
                kr.save(keys).map_err(|e| {
                    GatewayError::Internal(format!("failed to persist approver keyring: {e}"))
                })
            }
            KeyringPersistence::Store => {
                // Serialise under the lock, write outside it: a store round trip can block, and the
                // keyring lock is taken on the approval read path.
                let json = {
                    let kr =
                        self.approver_keyring.read().expect("approver keyring lock not poisoned");
                    kr.to_json().map_err(|e| {
                        GatewayError::Internal(format!("approver keyring could not be encoded: {e}"))
                    })?
                };
                self.store.put_meta(APPROVER_KEYRING_META, &json)?;
                // The refresh clock is deliberately NOT stamped here. It records when this instance
                // last READ, and [`Self::mutate_keyring`] has already stamped it for the read that
                // opened this critical section; stamping again on the way out would let a busy writer
                // keep pushing the deadline forward without ever seeing another instance's writes.
                Ok(())
            }
        }
    }

    /// The effective **approval floor**: what a bare operator bearer may resolve on this gateway.
    ///
    /// Resolution order (most authoritative first):
    /// 1. `PERMAURA_REQUIRE_DEVICE_SIGNED_APPROVAL=1` forces `DeviceSigned` (an escape hatch for
    ///    a gateway with nothing enrolled yet); nothing overrides it.
    /// 2. An explicit operator override (set over loopback) wins next: this is the opt-DOWN to
    ///    `Approve` that re-enables bearer-resolvable `approve`-tier approvals after pairing, or an
    ///    explicit `DeviceSigned`.
    /// 3. Otherwise enrolment decides: once ANY approver device has been enrolled the floor is
    ///    `DeviceSigned` (the default-on rule, sticky across revocation via
    ///    `ever_enrolled`), else `Approve` (the pre-pairing world, unchanged).
    pub fn approval_floor(&self) -> ApprovalFloor {
        self.refresh_keyring_if_stale();
        let forced = std::env::var("PERMAURA_REQUIRE_DEVICE_SIGNED_APPROVAL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if forced {
            return ApprovalFloor::DeviceSigned;
        }
        if let Some(f) = *self.approval_floor.read().expect("approval floor lock not poisoned") {
            return f;
        }
        // Enrolment used to decide this: pairing any device raised the floor by itself, and every
        // per-action rung a policy had set was overridden from that moment on. That made the policy
        // editor a lie (you chose which actions were worth a signature, and pairing a phone silently
        // answered "all of them"), and it made pairing a surprise, because the console stopped being
        // able to approve anything with no screen having said it would.
        //
        // The policy decides now. A `device_signed` rung still refuses a bearer whatever this returns
        // (the per-approval gate in `rest::resolve_approval`), so pairing a device is what makes those
        // rungs resolvable rather than what changes what they mean. Raising the floor to blanket
        // device-signed is offered at first pairing and settable any time; it is simply no longer
        // assumed.
        //
        // Existing gateways are not loosened by this. A stored floor is written for any gateway that
        // already had a device enrolled when it upgraded, so it keeps exactly the floor it had;
        // see `adopt_enrolment_floor`.
        ApprovalFloor::Approve
    }

    /// Whether an operator has EXPLICITLY opted this gateway's approvals down to `approve`.
    ///
    /// Distinct from `approval_floor() == Approve`, which is now also the default, and the difference
    /// is what the anti-brick clauses turn on. A gateway that simply never opted in must still hold a
    /// remote control-plane write for a device signature: that protection was never about approvals
    /// and must not weaken because approvals stopped being blanket-signed. A gateway whose operator
    /// paid the step-up to opt down must not hold them, or the opt-down buys nothing and a tenant who
    /// lost their only device stays frozen.
    fn approvals_opted_down(&self) -> bool {
        matches!(
            *self.approval_floor.read().expect("approval floor lock not poisoned"),
            Some(ApprovalFloor::Approve)
        )
    }

    /// The floor override as stored, `None` when enrolment and policy decide. Distinct from
    /// [`Self::approval_floor`], which reads `Approve` for both an untouched gateway and one an
    /// operator explicitly opted down; every surface that reports the floor reports this beside it.
    pub fn stored_approval_floor(&self) -> Option<ApprovalFloor> {
        self.refresh_keyring_if_stale();
        *self.approval_floor.read().expect("approval floor lock not poisoned")
    }

    /// Whether the stored opt-down was written while no device was trusted, and so was confirmed by
    /// nothing a device holder controls. Read when the next first device is paired, which clears it.
    pub fn opt_down_unanchored(&self) -> Result<bool, GatewayError> {
        Ok(self.store.get_meta(APPROVAL_FLOOR_UNANCHORED_META)?.is_some_and(|v| v == "1"))
    }

    /// Record whether the floor just written is an opt-down nothing trusted confirmed.
    pub fn set_opt_down_unanchored(&self, unanchored: bool) -> Result<(), GatewayError> {
        self.store.put_meta(APPROVAL_FLOOR_UNANCHORED_META, if unanchored { "1" } else { "" })
    }

    /// Give a gateway that already had a device enrolled the floor it has been running with.
    ///
    /// Called at startup, and meant to do its work once in a gateway's life: the first start that has it
    /// records [`APPROVAL_FLOOR_ADOPTED_META`], and a later start that reads the marker returns at once; a
    /// start that cannot read it, or whose raise or marker write failed, adopts again, taking the stricter floor. Without it,
    /// upgrading past the change above would silently drop every deployed gateway with a paired device
    /// from blanket device-signed to policy-decides, a real loosening, applied to installations whose
    /// operators never asked for it and would not be told. Writing the value they already had makes the
    /// new default apply only to gateways that pair a device from here on, which is the only population
    /// that gets to make the choice. Run again, it would undo exactly that: a device paired after the
    /// first start, or an override its owner cleared since, would come back from the next restart as the
    /// blanket floor.
    pub fn adopt_enrolment_floor(&self) {
        match self.store.get_meta(APPROVAL_FLOOR_ADOPTED_META) {
            Ok(Some(done)) if done == "1" => return,
            Ok(_) => {}
            // Unreadable: adopting is the stricter guess, and a raise is what the operator can undo.
            Err(e) => tracing::error!(error = %e, "could not read whether the approval floor was already adopted"),
        }
        let stored = self.approval_floor.read().expect("approval floor lock not poisoned").is_some();
        self.refresh_keyring_if_stale();
        let enrolled = self
            .approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .ever_enrolled();
        if !stored && enrolled {
            if let Err(e) = self.set_approval_floor(Some(ApprovalFloor::DeviceSigned)) {
                // Fail loud, leave the in-memory value alone and the marker unwritten, so the next start
                // tries again: `set_approval_floor` forces the strict value in on a failed raise, so this
                // gateway is still enforcing what it was.
                tracing::error!(error = %e, "could not record the approval floor this gateway was already running with");
                return;
            }
            tracing::info!("recorded the existing device-signed approval floor explicitly");
        }
        if let Err(e) = self.store.put_meta(APPROVAL_FLOOR_ADOPTED_META, "1") {
            tracing::error!(error = %e, "could not record that the approval floor was adopted; the next start adopts it again");
        }
    }

    /// Whether EVERY bearer-only resolution must be refused (the floor sits at `DeviceSigned`).
    /// Retained as the coarse global check; the per-approval gate additionally refuses a
    /// `device_signed`-tier approval even when the floor is `Approve`.
    pub fn require_device_signed_approval(&self) -> bool {
        self.approval_floor() == ApprovalFloor::DeviceSigned
    }

    /// Whether any approver device has ever been enrolled (revoked ones included; the same sticky
    /// signal that arms the default-on floor). The broker policy-mutation guard uses it to decide whether a
    /// non-tightening remote control-plane write must be held for a device signature.
    pub fn any_device_enrolled(&self) -> bool {
        self.refresh_keyring_if_stale();
        self.approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .ever_enrolled()
    }

    /// Whether a control-plane mutation arriving over the broker must be HELD for a device
    /// signature: the caller is remote, a device has ever been enrolled, AND this gateway still
    /// requires a device signature at all.
    ///
    /// The floor clause is the anti-brick half, and it is not a relaxation of the sticky
    /// `ever_enrolled` rule; it is what stops that rule outliving its own escape hatch. A hold is
    /// only worth placing if something can resolve it, and the tier every control-plane hold carries
    /// is `device_signed`. Lower the floor to `Approve` and nothing changes for those holds: they are
    /// still queued at a tier the per-approval gate refuses to bearer-resolve, so a tenant who has
    /// lost their only device finds that the loosening they just performed bought them nothing and
    /// their control plane is still frozen. That loosening is not cheap to reach: on a hosted worker
    /// it takes an owner-scoped, single-use step-up ticket and, while any usable device remains, a
    /// co-signature from that device; on a self-run or tunnelled gateway it can only be set from the
    /// gateway's own host. On a self-run gateway a compromised control plane cannot bring the
    /// precondition about, which is why reading it here does not re-open the "revoke your way back to
    /// bearer approvals" path the sticky flag exists to close. On a hosted worker it can once no
    /// usable device remains, since owner step-up tickets from permaura.com can revoke the last device
    /// and then lower the floor, though the chain records each step.
    pub fn control_plane_hold_required(&self, remote: bool) -> bool {
        remote && self.any_device_enrolled() && !self.approvals_opted_down()
    }

    /// Whether a **usable** (non-revoked) trusted key exists, distinct from
    /// [`Self::any_device_enrolled`], which is sticky across revocation.
    ///
    /// This is the predicate that decides whether the next device enrolment can be held for a
    /// co-signature at all. Only a usable key can co-sign: `trusted_key` returns `None` for a revoked
    /// approver, so a hold placed on the strength of `ever_enrolled` would be a hold no device on
    /// earth could satisfy. On a self-run gateway that is merely awkward: the owner is sitting at the
    /// host and pairs a replacement over loopback. On a hosted worker there is no host to sit at, so
    /// the tenant would be permanently locked out of ever pairing again: pair one device, revoke it,
    /// and the sticky flag says "hold for a co-signature" forever while nothing can ever sign.
    ///
    /// [`Self::any_device_enrolled`] deliberately keeps the sticky rule for the broker's ordinary
    /// mutation guard. There, refusing a policy change bricks nothing, and the recovery path is to
    /// pair a replacement device, which is exactly what this predicate keeps reachable.
    pub fn any_device_trusted(&self) -> bool {
        self.refresh_keyring_if_stale();
        !self
            .approver_keyring
            .read()
            .expect("approver keyring lock not poisoned")
            .is_empty()
    }

    /// Whether a vault export must be signed on a paired device before it runs.
    ///
    /// **Deliberately not `remote`-gated, unlike [`Self::control_plane_hold_required`].** That guard
    /// trusts loopback because whoever reaches it is assumed to be the owner sitting at the host. On a
    /// developer's machine that assumption is false in the exact way this product exists to address:
    /// an agent running as the same OS user *is* loopback, and it can read
    /// `$PERMAURA_HOME/operator.token` (mode 0600, and therefore readable by every process that user
    /// runs) to mint itself an Operator session. Export is the one call that turns that local read
    /// into every credential in the estate, so it is held wherever it arrives from, unless the
    /// operator has explicitly opted approvals down to `approve`.
    ///
    /// The predicate is [`Self::any_device_trusted`], NOT the sticky `any_device_enrolled`, and that
    /// is the difference between a control and a brick: the sticky flag survives revocation, so a
    /// machine that paired a device and then revoked it would hold for a signature nothing on earth
    /// could produce, with no way out. It also *is* the rule as stated: a registered device must sign
    /// off, and where there is none the export proceeds, which is what keeps an estate whose only
    /// route out is an export from being stranded. A flat refusal was tried and reverted for exactly
    /// that reason.
    pub fn vault_export_hold_required(&self) -> bool {
        self.any_device_trusted() && !self.approvals_opted_down()
    }

    /// Hold a vault export as a `device_signed` approval.
    ///
    /// **No passphrase material is stored, and that is a decision rather than an oversight.** Binding
    /// the passphrase into `request_hash` the way a held mutation binds its diff would persist a
    /// digest of a user-chosen secret in the approvals table, offline-crackable by anyone who reaches
    /// the store, which on the same-user threat this exists for is the attacker. What the device
    /// signs is a random nonce: the approval authorises *an export, now, confirmed by a human*, and
    /// the passphrase arrives again on the resuming call. A swapped passphrase is the narrow thing
    /// that buys an attacker nothing they did not already have, since whoever resumes the call
    /// receives the bundle regardless of which passphrase seals it.
    ///
    /// **Collected only by the caller that asked.** The approval list is open to every operator bearer,
    /// so an approval id is not a capability: the 202 carries a single-use resume secret, and only its
    /// SHA-256 is kept here. The approval also lapses after [`EXPORT_APPROVAL_TTL_MS`] unless collected.
    pub fn hold_vault_export_approval(
        &self,
        capability: &str,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Result<(PendingApproval, String), GatewayError> {
        let created_at = now_ms();
        let resume_secret = crate::oauth_connect::random_token();
        let approval = PendingApproval {
            id: format!("appr_{}", short_id()),
            session_id: String::new(),
            capability: capability.to_string(),
            resource: crate::rest::VAULT_RESOURCE.to_string(),
            message: message.to_string(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            // A nonce, not the request. See the note above on why the passphrase is absent.
            params: serde_json::json!({
                "nonce": short_id(),
                "resume_sha256": export_resume_digest(&resume_secret),
            }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at,
            expires_at: Some(created_at + EXPORT_APPROVAL_TTL_MS),
            // Not a guess from the capability name: an export produces one file holding every
            // credential this gateway has, which is the definition the Critical tier carries.
            risk: Some(permaura_core::RiskTier::Critical),
            action_description: Some(
                "Produce a single file containing every credential in this gateway, sealed under \
                 the requester's passphrase."
                    .to_string(),
            ),
            intent: None,
            required_tier: "device_signed".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: self.with_required_independence(requested_by),
        };
        self.store.insert_approval(approval.clone())?;
        // Everything the control plane is told is read off the row, including the grade: this hold has
        // no capability behind it, so `risk_label()` answers `unknown`, which is what its own 202 says
        // too. An invented tier on the highest-consequence hold in the system would be the worst place
        // for one.
        let announce_to = self.announcer.links();
        tokio::spawn(crate::announce::announce_hold(announce_to, crate::announce::AnnouncedHold {
            approval_id: approval.id.clone(),
            capability: approval.capability.clone(),
            resource: approval.resource.clone(),
            risk: approval.risk_label(),
            required_tier: approval.required_tier.clone(),
            agent: None,
            expires_at: approval.expires_at,
            requested_by: approval.requested_by.clone(),
        }));
        let tokens = self.push.tokens();
        if !tokens.is_empty() {
            tokio::spawn(crate::push::send_expo_push(
                tokens,
                crate::push::PushKind::ApprovalRequested,
                approval.id.clone(),
            ));
        }
        Ok((approval, resume_secret))
    }

    /// The title an approver reads for `mutation`, with the names this gateway has for what it touches
    /// read now, so a later rename cannot change what a held change says it is.
    pub fn describe_mutation(&self, mutation: &crate::policy_guard::Mutation) -> String {
        mutation.summary_in(&HoldNames { service: self })
    }

    /// Hold a control-plane mutation as a `device_signed` approval: the mutation is stored verbatim
    /// as the approval's `params` (so `request_hash` binds the exact diff a device then signs), and
    /// pushed to the operator's enrolled device(s). Applied only on a verified device signature via
    /// [`Self::resolve_approval`]'s `permaura.policy.write` special-case.
    ///
    /// The same mutation already waiting is answered with the hold that is waiting, not held again. A
    /// client that retries a slow 202 is asking for the same thing twice, and two holds for one change
    /// put two cards in front of the approver, one of which is left pending after the other is signed.
    /// Every caller holds the control-plane lock, so nothing can create the twin between the look and
    /// the write.
    ///
    /// Synchronous, for a change whose quorum the estate cannot raise
    /// ([`crate::policy_guard::quorum_without_estate`]): an agent, a staged credential, a device. Any other change is
    /// held through [`Self::hold_change_approval`], which works its quorum out off the runtime, and is refused here.
    pub fn hold_mutation_approval(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Result<PendingApproval, GatewayError> {
        let quorum = estate_free_quorum(mutation)?;
        self.hold_mutation_approval_at(capability, mutation, message, requested_by, true, quorum, None)
    }

    /// [`Self::hold_mutation_approval`] for any change, its quorum and what it loosens worked out by
    /// [`Self::held_change_bar`]. Its effect and estate digest are kept beside the hold, for the confirm to compare with.
    pub async fn hold_change_approval(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Result<PendingApproval, GatewayError> {
        let (quorum, _, effect) = self.held_change_bar(mutation, false, None).await?;
        self.hold_mutation_approval_at(capability, mutation, message, requested_by, true, quorum, Some(&effect))
    }

    /// [`Self::hold_mutation_approval`] for one of a set of changes whose rows the caller has checked against the held-changes budget together ([`Self::refuse_over_control_plane_hold_bytes`]), under the control-plane lock it still holds, so a set admitted together is never refused part-way.
    pub fn hold_admitted_mutation_approval(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Result<PendingApproval, GatewayError> {
        let quorum = estate_free_quorum(mutation)?;
        self.hold_mutation_approval_at(capability, mutation, message, requested_by, false, quorum, None)
    }

    fn hold_mutation_approval_at(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
        check_budget: bool,
        quorum: u8,
        effect: Option<&HeldEffectRecord>,
    ) -> Result<PendingApproval, GatewayError> {
        let params = self.held_mutation_params(mutation)?;
        if let Some(waiting) = self.pending_control_plane_hold(capability, &params)? {
            if !independence_revoked_since(&self.approver_keyring_snapshot(), &waiting) {
                tracing::info!(
                    approval_id = %waiting.id,
                    "this change is already held; answering with the hold that is waiting rather than holding it again"
                );
                return Ok(waiting);
            }
            self.retire_stranded_hold(waiting)?;
        }
        let approval = self.control_plane_hold_row(capability, mutation, params, message, requested_by, quorum)?;
        if check_budget {
            self.admit_control_plane_hold(&approval)?;
        }
        // Before the row, so a hold the confirm can find always has what it loosened beside it.
        if let Some(effect) = effect.filter(|e| e.effect != crate::policy_guard::HeldEffect::NotBinding) {
            let text = serde_json::to_string(effect)
                .map_err(|e| GatewayError::Internal(format!("what a held change loosens could not be encoded: {e}")))?;
            self.store.put_meta(&format!("{HELD_EFFECT_META_PREFIX}{}", approval.id), &text)?;
        }
        self.store.insert_approval(approval.clone())?;
        // Same as the vault export: no capability, so the captured grade is `unknown`.
        let announce_to = self.announcer.links();
        tokio::spawn(crate::announce::announce_hold(announce_to, crate::announce::AnnouncedHold {
            approval_id: approval.id.clone(),
            capability: approval.capability.clone(),
            resource: approval.resource.clone(),
            risk: approval.risk_label(),
            required_tier: approval.required_tier.clone(),
            agent: None,
            expires_at: approval.expires_at,
            requested_by: approval.requested_by.clone(),
        }));
        let tokens = self.push.tokens();
        if !tokens.is_empty() {
            tokio::spawn(crate::push::send_expo_push(
                tokens,
                crate::push::PushKind::ApprovalRequested,
                approval.id.clone(),
            ));
        }
        self.audit_mutation("requires_approval", &approval, "held", None, None, None)?;
        Ok(approval)
    }

    /// A held mutation's `params`: the mutation as serde_json writes it, with the digest of the row it was asked against when it edits one.
    fn held_mutation_params(&self, mutation: &crate::policy_guard::Mutation) -> Result<JsonText, GatewayError> {
        let mut params = serde_json::to_value(mutation)
            .map_err(|e| GatewayError::Internal(format!("held mutation could not be encoded: {e}")))?;
        if let (Some(base), Some(fields)) = (crate::rest::held_row_digest(self.store.as_ref(), mutation)?, params.as_object_mut()) {
            fields.insert(crate::rest::HELD_BASE_KEY.into(), serde_json::Value::String(base));
        }
        Ok(JsonText::from_value(&params))
    }

    /// The row [`Self::hold_mutation_approval`] writes for `mutation`, built and written nowhere.
    fn control_plane_hold_row(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        params: JsonText,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
        quorum: u8,
    ) -> Result<PendingApproval, GatewayError> {
        let created_at = now_ms();
        Ok(PendingApproval {
            id: format!("appr_{}", short_id()),
            session_id: String::new(), // a control-plane change has no requesting agent session
            capability: capability.to_string(),
            resource: crate::store::CONTROL_PLANE_RESOURCE.to_string(),
            message: message.to_string(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params,
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at,
            expires_at: Some(control_plane_hold_expiry(created_at)),
            // Every mutation that reaches this function has already failed the tightening test, so
            // it is a change that can grant more access than the estate has now, which is the band
            // Critical describes, whatever the individual mutation happens to be.
            risk: Some(permaura_core::RiskTier::Critical),
            action_description: Some(self.describe_mutation(mutation)),
            intent: None,
            required_tier: "device_signed".into(),
            // A change that lowers a two-person rule needs the two people the rule does.
            required_signatures: quorum,
            signatures: Vec::new(),
            requested_by: self.with_required_independence(requested_by),
        })
    }

    /// The stored bytes [`Self::hold_mutation_approval`] would write for `mutation`, for a caller that holds several changes at once and checks them against the budget together first.
    pub fn control_plane_hold_bytes(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        message: &str,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Result<u64, GatewayError> {
        let quorum = estate_free_quorum(mutation)?;
        let params = self.held_mutation_params(mutation)?;
        Ok(crate::store::row_len(&self.control_plane_hold_row(capability, mutation, params, message, requested_by, quorum)?))
    }

    /// Refuse a control-plane hold that would take the pending ones past the held-params ceiling, writing nothing.
    /// A member chooses how large a held change is, up to the body limit of the route it arrives on, and a hold waits for a device, so these rows are bounded as an agent's held calls are. They have a budget of their own the same size, so neither kind of hold can fill the other's. Every caller holds the control-plane lock, so the check and the write are one step.
    fn admit_control_plane_hold(&self, approval: &PendingApproval) -> Result<(), GatewayError> {
        self.refuse_over_control_plane_hold_bytes(crate::store::row_len(approval), 1)
    }

    /// Refuse `holds` control-plane holds taking `adding` stored bytes together when they would take the pending ones past the held-params ceiling.
    /// Changes alone in the queue, one or a vault import's set, are held whatever their rows take, so none is refused where no retry could clear it ([`crate::memory::control_plane_held_total_bytes`]).
    pub fn refuse_over_control_plane_hold_bytes(&self, adding: u64, holds: usize) -> Result<(), GatewayError> {
        let pending = self.store.pending_control_plane_hold_bytes()?;
        let ceiling = self.memory.control_plane_held_total_bytes();
        if pending > 0 && pending.saturating_add(adding) > ceiling {
            let these = if holds == 1 { "this one".to_string() } else { format!("these {holds} ({adding} bytes)") };
            return Err(GatewayError::TooManyRequests {
                reason: "held_params".to_string(),
                message: format!(
                    "the changes already waiting for a device on this gateway hold {pending} bytes, and {these} would take them past the {ceiling}-byte ceiling; confirm or deny some before asking for another"
                ),
                retry_after_secs: HELD_PARAMS_RETRY_AFTER_SECS,
                scope: None,
            });
        }
        Ok(())
    }

    /// How many distinct devices a held `mutation` needs ([`crate::policy_guard::hold_quorum_with_marks`]) and, when
    /// `with_lowered`, the actions it puts below their high-water mark with each mark, from the store as it stands and
    /// the marks. The store is read here and the estate resolved on the blocking pool: past a few grants with their own
    /// expiries that is the expensive part of a held change, and a runtime worker held by it answers nothing else. The
    /// quorums in force before the change, and after it when it lowers a mark, are kept for the marks its apply notes
    /// and settles. `kept` is what the change lowered when it was held, at a confirm: the agents named then are resolved
    /// by id, and a change whose effect could not be worked out then or now needs
    /// [`crate::policy_guard::past_budget_quorum`].
    pub(crate) async fn held_change_bar(
        &self,
        mutation: &crate::policy_guard::Mutation,
        with_lowered: bool,
        kept: Option<&crate::policy_guard::HeldEffect>,
    ) -> Result<(u8, Vec<(crate::policy_guard::ActionKey, u8)>, HeldEffectRecord), GatewayError> {
        use crate::policy_guard::HeldEffect;
        if let Some(quorum) = crate::policy_guard::quorum_without_estate(mutation) {
            if with_lowered && crate::rest::notes_quorum_marks(mutation) {
                self.prepare_quorum_marks(self.store.list_policies()?, self.store.list_grants()?).await?;
            }
            return Ok((quorum, Vec::new(), HeldEffectRecord { effect: HeldEffect::NotBinding, estate_digest: None }));
        }
        let also = match kept {
            Some(HeldEffect::Lowers(then)) => then.named.clone(),
            _ => Vec::new(),
        };
        let unknown_then = matches!(kept, Some(HeldEffect::PastBudget));
        let policies = self.store.list_policies()?;
        let grants = self.store.list_grants()?;
        let stored = self.stored_quorum_marks()?;
        let reachable = self.approver_keyring_snapshot().reachable_people();
        let mutation = mutation.clone();
        let (quorum, lowered, effect, before, after) = self.classify(move || {
            let in_force = crate::policy_guard::quorums_in_force(&policies, &grants);
            let marks = raised_marks(stored, &in_force);
            let ctx = crate::policy_guard::GuardContext { policies: &policies, grants: &grants, connections: &[], agents: &[] };
            let mut quorum = crate::policy_guard::hold_quorum_with_marks(&mutation, &ctx, &marks, reachable);
            let lowered: Vec<(crate::policy_guard::ActionKey, u8)> = if with_lowered {
                let (_, keys) = crate::policy_guard::high_water_quorum(&mutation, &ctx, &marks);
                keys.into_iter().map(|k| { let q = marks.get(&k).copied().unwrap_or(1); (k, q) }).collect()
            } else {
                Vec::new()
            };
            let after = if lowered.is_empty() { None } else { crate::policy_guard::estate_after(&mutation, &ctx) }
                .map(|(p, g)| { let in_force = crate::policy_guard::quorums_in_force(&p, &g); (estate_digest(&p, &g), in_force) });
            let effect = crate::policy_guard::held_effect(&mutation, &ctx, &also);
            if unknown_then || matches!(effect, HeldEffect::PastBudget) {
                quorum = quorum.max(crate::policy_guard::past_budget_quorum(&mutation, &ctx, &marks));
            }
            (quorum, lowered, effect, (estate_digest(&policies, &grants), in_force), after)
        })
        .await?;
        let effect = HeldEffectRecord { effect, estate_digest: Some(before.0) };
        self.remember_in_force(before);
        if let Some(after) = after {
            self.remember_in_force(after);
        }
        Ok((quorum, lowered, effect))
    }

    /// The held effect and estate digest, or `None` when nothing was kept: a change that moves
    /// no policy or grant, or one held before this gateway kept it. An unreadable record is an error rather than none.
    fn kept_effect(&self, approval_id: &str) -> Result<Option<HeldEffectRecord>, GatewayError> {
        let Some(text) = self.store.get_meta(&format!("{HELD_EFFECT_META_PREFIX}{approval_id}"))?.filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Stored {
            Current(HeldEffectRecord),
            Legacy(crate::policy_guard::HeldEffect),
        }
        serde_json::from_str(&text)
            .map(|stored| Some(match stored {
                Stored::Current(record) => record,
                Stored::Legacy(effect) => HeldEffectRecord { effect, estate_digest: None },
            }))
            .map_err(|e| GatewayError::Internal(format!("what held change '{approval_id}' loosened is unreadable: {e}")))
    }

    /// Empty the kept effect of a hold that has ended. Best effort: a record left behind is never read again.
    fn forget_kept_effect(&self, approval_id: &str) {
        if let Err(e) = self.store.put_meta(&format!("{HELD_EFFECT_META_PREFIX}{approval_id}"), "") {
            tracing::warn!(approval_id = %approval_id, error = %e, "what an ended held change loosened was not cleared");
        }
    }

    /// End a held change whose effect grew after it was held, so that applying it now would lower something no signer
    /// saw it lower. It is denied with [`DENIED_EFFECT_WIDENED`] and has to be asked for again, when it is held against
    /// the estate as it now is. Answers whether this call ended it.
    fn retire_widened_hold(&self, mut held: PendingApproval) -> Result<bool, GatewayError> {
        if !self.store.claim_once("approval-resolution", &held.id, i64::MAX)? {
            return Ok(false);
        }
        held.status = "denied".into();
        held.resolution_reason = Some(DENIED_EFFECT_WIDENED.to_string());
        self.audit_mutation("denied", &held, "effect_widened", None, None, None)?;
        let id = held.id.clone();
        self.settle_approval(held)?;
        self.forget_kept_effect(&id);
        Ok(true)
    }

    /// The worker owns its permit until classification ends, even if its caller is canceled.
    pub(crate) async fn classify<T: Send + 'static>(&self, work: impl FnOnce() -> T + Send + 'static) -> Result<T, GatewayError> {
        let slot = self.classification_slots.clone().acquire_owned().await.map_err(|e| GatewayError::Internal(e.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            work()
        }).await.map_err(|e| GatewayError::Internal(format!("the change could not be classified: {e}")))
    }

    /// Resolve the quorums in force under `policies` and `grants` on the blocking pool and keep them, ahead of an apply
    /// whose marks would otherwise resolve them on this worker.
    pub(crate) async fn prepare_quorum_marks(&self, policies: Vec<permaura_core::Policy>, grants: Vec<permaura_core::Grant>) -> Result<(), GatewayError> {
        let entry = self.classify(move || {
            let in_force = crate::policy_guard::quorums_in_force(&policies, &grants);
            (estate_digest(&policies, &grants), in_force)
        })
        .await?;
        self.remember_in_force(entry);
        Ok(())
    }

    /// The quorums in force under `policies` and `grants` ([`crate::policy_guard::quorums_in_force`]), kept from a change
    /// that resolved this estate off the runtime, or resolved here.
    fn in_force(&self, policies: &[permaura_core::Policy], grants: &[permaura_core::Grant]) -> std::collections::BTreeMap<crate::policy_guard::ActionKey, u8> {
        let digest = estate_digest(policies, grants);
        let kept = self.in_force_cache.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(key, _)| key == &digest).map(|(_, m)| m.clone());
        kept.unwrap_or_else(|| crate::policy_guard::quorums_in_force(policies, grants))
    }

    fn remember_in_force(&self, (digest, in_force): InForce) {
        let mut kept = self.in_force_cache.lock().unwrap_or_else(|e| e.into_inner());
        kept.retain(|(key, _)| key != &digest);
        kept.push((digest, in_force));
        if kept.len() > IN_FORCE_KEPT {
            kept.remove(0);
        }
    }

    /// `requested_by` with the independence confirming it takes, read off the keyring as the hold is created.
    fn with_required_independence(
        &self,
        requested_by: Option<crate::store::HoldRequester>,
    ) -> Option<crate::store::HoldRequester> {
        requested_by.map(|mut requester| {
            requester.required_independence = self.approver_keyring_snapshot().most_independent(&requester);
            requester
        })
    }

    /// Deny a waiting control-plane hold that [`independence_revoked_since`] says nobody can confirm, because
    /// the same change is being asked for again and would otherwise be answered with it. Not cleaned up as a
    /// denial is, since the hold that replaces it carries the same change and whatever it staged.
    fn retire_stranded_hold(&self, mut waiting: PendingApproval) -> Result<(), GatewayError> {
        if !self.store.claim_once("approval-resolution", &waiting.id, i64::MAX)? {
            return Ok(());
        }
        waiting.status = "denied".into();
        waiting.resolution_reason = Some(DENIED_INDEPENDENCE_REVOKED.to_string());
        self.audit_mutation("denied", &waiting, "superseded", None, None, None)?;
        let id = waiting.id.clone();
        self.settle_approval(waiting)?;
        self.forget_kept_effect(&id);
        Ok(())
    }

    /// The stored quorum high-water marks. An unreadable row is an error rather than no marks, because
    /// no marks is the loosest answer.
    fn stored_quorum_marks(&self) -> Result<std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>, GatewayError> {
        let Some(raw) = self.store.get_meta(QUORUM_HIGH_WATER_META)?.filter(|r| !r.trim().is_empty()) else {
            return Ok(Default::default());
        };
        let rows: Vec<(String, String, u8)> = serde_json::from_str(&raw)
            .map_err(|e| GatewayError::Internal(format!("the quorum high-water marks are unreadable: {e}")))?;
        Ok(rows.into_iter().map(|(conn, action, q)| ((conn, action), q)).collect())
    }

    fn put_quorum_marks(&self, marks: &std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>) -> Result<(), GatewayError> {
        let rows: Vec<(&str, &str, u8)> =
            marks.iter().filter(|(_, q)| **q > 1).map(|((conn, action), q)| (conn.as_str(), action.as_str(), *q)).collect();
        let raw = serde_json::to_string(&rows)
            .map_err(|e| GatewayError::Internal(format!("the quorum high-water marks could not be encoded: {e}")))?;
        self.store.put_meta(QUORUM_HIGH_WATER_META, &raw)
    }

    /// The stored marks raised to every quorum above one in force under `policies` and `grants`.
    fn quorum_marks_with(
        &self,
        policies: &[permaura_core::Policy],
        grants: &[permaura_core::Grant],
    ) -> Result<std::collections::BTreeMap<crate::policy_guard::ActionKey, u8>, GatewayError> {
        Ok(raised_marks(self.stored_quorum_marks()?, &self.in_force(policies, grants)))
    }

    /// Record every quorum above one in force now, before a policy or grant change that could take a rule
    /// out of force applies. Marks only ever rise here.
    pub fn note_quorum_marks(&self) -> Result<(), GatewayError> {
        let stored = self.stored_quorum_marks()?;
        let marks = self.quorum_marks_with(&self.store.list_policies()?, &self.store.list_grants()?)?;
        if marks != stored {
            self.put_quorum_marks(&marks)?;
        }
        Ok(())
    }

    /// After a held change signed by `signed` people has applied, the mark on each action it lowered that
    /// it was signed at is replaced by what is in force now: the people the mark stood for agreed.
    pub(crate) fn settle_quorum_marks(&self, lowered: &[(crate::policy_guard::ActionKey, u8)], signed: u8) -> Result<(), GatewayError> {
        if lowered.is_empty() {
            return Ok(());
        }
        let in_force = self.in_force(&self.store.list_policies()?, &self.store.list_grants()?);
        let mut marks = self.stored_quorum_marks()?;
        for (key, mark) in lowered {
            if signed >= *mark {
                match in_force.get(key) {
                    Some(q) => {
                        marks.insert(key.clone(), *q);
                    }
                    None => {
                        marks.remove(key);
                    }
                }
            }
        }
        self.put_quorum_marks(&marks)
    }

    /// Refuse to resolve `approval` with `method` when that falls short of what it needs now: `rung`
    /// with `quorum` distinct live signatures, which may be more than it needed when it was held. The
    /// pending row is raised to match, so the devices it now needs can still sign it.
    ///
    /// A `device_signed` resolution at a quorum of one is the caller's verified signature; above one,
    /// the signatures recorded on the row are counted with the same live-key rule as the quorum.
    fn refuse_short_of(
        &self,
        approval: &PendingApproval,
        method: &str,
        rung: Rung,
        quorum: u8,
    ) -> Result<(), GatewayError> {
        if rung < Rung::DeviceSigned {
            return Ok(());
        }
        let quorum = quorum.max(1);
        let signed = live_people_count(&self.approver_keyring_snapshot(), &approval.signatures);
        if method == "device_signed" && (quorum == 1 || signed >= quorum) {
            return Ok(());
        }
        let short = |row: &PendingApproval| row.required_tier != "device_signed" || row.required_signatures < quorum;
        // Both only ever rise, so a row read already raised needs no unit of work.
        if short(approval) {
            self.locked_store_section(&self.signature_lock, || {
                if let Some(mut row) = self.store.get_approval(&approval.id)? {
                    if row.status == "pending" && short(&row) {
                        row.required_tier = "device_signed".into();
                        row.required_signatures = row.required_signatures.max(quorum);
                        self.store.put_approval(row)?;
                    }
                }
                Ok(())
            })?;
        }
        Err(GatewayError::Denied(if method == "device_signed" {
            format!(
                "approval '{}' now needs signatures from {quorum} different people's paired devices and has {signed}; it stays pending until the rest sign",
                approval.id
            )
        } else {
            format!(
                "approval '{}' is now for an action that needs a device-signed approval; resolve it from a paired approval device",
                approval.id
            )
        }))
    }

    /// A pending control-plane hold whose mutation is exactly `params`, if one is waiting.
    fn pending_control_plane_hold(
        &self,
        capability: &str,
        held: &JsonText,
    ) -> Result<Option<PendingApproval>, GatewayError> {
        let now = now_ms();
        // A row keeps the text serde_json wrote from the mutation, so two equal mutations are equal texts.
        Ok(self.store.list_pending_control_plane_holds()?.into_iter().find(|a| {
            a.capability == capability
                && a.required_tier == "device_signed"
                && !a.is_expired(now)
                && a.params.get() == held.get()
        }))
    }

    /// Retire every held control-plane change whose deadline passed before `now`: the row becomes [`crate::store::APPROVAL_EXPIRED`], the audit chain records it, anything it staged is released, and the control plane is told it stopped waiting. Returns the ids retired by this sweep.
    ///
    /// A note that the hold's expiry is owed, the claim and the expired row are written as one unit, the note first, so a failure leaves either nothing (the hold stays pending for the next sweep) or the note, from which the next sweep finishes the expiry. The audit record is appended after the unit, since an audit append cannot run inside one, and one that could not be written is written by the next sweep from the same note. A hold a resolution has already claimed is left to that resolution.
    pub fn retire_expired_holds(&self, now: i64) -> Result<Vec<String>, GatewayError> {
        self.record_owed_expiries();
        let mut retired = Vec::new();
        for approval in self.store.list_pending_control_plane_holds()? {
            if !approval.is_expired(now) {
                continue;
            }
            let expired = self.locked_store_section(&self.signature_lock, || {
                let Some(mut row) = self.store.get_approval(&approval.id)? else { return Ok(None) };
                if row.status != "pending" || !row.is_expired(now) {
                    return Ok(None);
                }
                let mut owed = self.owed_expiry_records()?;
                owed.insert(row.id.clone());
                self.put_owed_expiry_records(&owed)?;
                if !self.store.claim_once("approval-resolution", &row.id, i64::MAX)? {
                    owed.remove(&row.id);
                    self.put_owed_expiry_records(&owed)?;
                    return Ok(None);
                }
                mark_expired(&mut row);
                self.store.put_approval(row.clone())?;
                Ok(Some(row))
            })?;
            let Some(row) = expired else { continue };
            if let Ok(mutation) = serde_json::from_str::<crate::policy_guard::Mutation>(row.params.get()) {
                crate::rest::cleanup_denied_mutation(self.store.as_ref(), &mutation);
            }
            self.forget_kept_effect(&row.id);
            let announce_to = self.announcer.links();
            tokio::spawn(crate::announce::announce_resolved(announce_to, row.id.clone()));
            tracing::info!(approval_id = %row.id, "a held change nobody confirmed within its deadline was retired; it has to be asked for again");
            if let Err(e) = self.record_expiry(&row) {
                tracing::warn!(approval_id = %row.id, error = %e, "the record of an expired held change could not be written; the next sweep writes it");
            }
            retired.push(row.id);
        }
        Ok(retired)
    }

    /// Append the audit record of `row`'s expiry, then strike it from the records owed.
    fn record_expiry(&self, row: &PendingApproval) -> Result<(), GatewayError> {
        self.audit_mutation("denied", row, "expired", None, None, None)?;
        self.locked_store_section(&self.signature_lock, || {
            let mut owed = self.owed_expiry_records()?;
            if owed.remove(&row.id) {
                self.put_owed_expiry_records(&owed)?;
            }
            Ok(())
        })
    }

    /// Write the records an earlier sweep expired a hold without managing to write. Best effort: what still fails stays owed.
    fn record_owed_expiries(&self) {
        let owed = match self.owed_expiry_records() {
            Ok(owed) => owed,
            Err(e) => {
                tracing::warn!(error = %e, "could not read the expiry records still owed");
                return;
            }
        };
        for id in owed {
            let outcome = match self.store.get_approval(&id) {
                Ok(Some(row)) if row.status == crate::store::APPROVAL_EXPIRED => self.record_expiry(&row),
                // Noted and claimed by an earlier sweep whose row write did not land: finish it.
                Ok(Some(mut row)) if row.status == "pending" && row.is_control_plane_hold() => {
                    mark_expired(&mut row);
                    self.locked_store_section(&self.signature_lock, || self.store.put_approval(row.clone()))
                        .and_then(|()| self.record_expiry(&row))
                }
                // Nothing to record against any more; the note is struck so it is not read again.
                Ok(_) => self.locked_store_section(&self.signature_lock, || {
                    let mut owed = self.owed_expiry_records()?;
                    if owed.remove(&id) {
                        self.put_owed_expiry_records(&owed)?;
                    }
                    Ok(())
                }),
                Err(e) => Err(e),
            };
            if let Err(e) = outcome {
                tracing::warn!(approval_id = %id, error = %e, "the record of an expired held change is still owed");
            }
        }
    }

    fn owed_expiry_records(&self) -> Result<std::collections::BTreeSet<String>, GatewayError> {
        let Some(raw) = self.store.get_meta(HOLD_EXPIRY_RECORDS_OWED_META)?.filter(|r| !r.trim().is_empty()) else {
            return Ok(Default::default());
        };
        serde_json::from_str(&raw).map_err(|e| GatewayError::Internal(format!("the expiry records owed are unreadable: {e}")))
    }

    fn put_owed_expiry_records(&self, owed: &std::collections::BTreeSet<String>) -> Result<(), GatewayError> {
        let raw = serde_json::to_string(owed)
            .map_err(|e| GatewayError::Internal(format!("the expiry records owed could not be encoded: {e}")))?;
        self.store.put_meta(HOLD_EXPIRY_RECORDS_OWED_META, &raw)
    }

    /// Cancel a delayed recovery an older build left on the clock, once, at boot.
    ///
    /// It replaces a periodic sweep that APPLIED one. Recovery that completes on a timer is gone:
    /// the operator bearer could silence the announcement it depended on, so the timer granted on its
    /// own what the bearer could not obtain.
    pub fn cancel_delayed_recovery(
        &self,
        now: i64,
    ) -> Result<Option<crate::recovery::PendingRecovery>, GatewayError> {
        crate::recovery::cancel_pending(self, now)
    }

    /// Append an audit event for a held control-plane mutation. Unlike [`Self::audit`] this needs no
    /// agent session or connector capability: the action id is the synthetic
    /// `permaura.policy.write` and the summary carries the resolution method + applied diff.
    fn audit_mutation(
        &self,
        decision: &str,
        approval: &PendingApproval,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
        applied: Option<&serde_json::Value>,
    ) -> Result<(), GatewayError> {
        let mut payload =
            AuditPayload::new(approval.capability.clone(), approval.resource.clone(), decision);
        payload.summary = serde_json::json!({
            "approval_id": approval.id,
            "method": method,
            "approver": approver,
            "mutation": applied.map(crate::audit_bound::recorded),
        });
        if let Some(requested_by) = &approval.requested_by {
            payload.summary["requested_by"] = serde_json::json!(requested_by);
        }
        self.approver_detail(approval, method, approver, actor, decision == "approved")
            .insert_into(&mut payload.summary);
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// Record a change of who may act (a session opened or revoked, an enrolment code minted or redeemed) under the session `by` that made it.
    ///
    /// The caller passes ids and facts only: a bearer or an enrolment code is never part of the record.
    pub fn audit_authority(
        &self,
        action: &str,
        resource: &str,
        by: &Session,
        mut summary: serde_json::Value,
    ) -> Result<(), GatewayError> {
        let mut payload = AuditPayload::new(action.to_string(), resource.to_string(), "allow");
        payload.user_id = by.user_id.clone();
        payload.agent_id = Some(by.agent_id.clone());
        payload.device_id = by.device_id.clone();
        payload.session_id = Some(by.id.clone());
        if let (Some(actor), Some(map)) = (&by.actor, summary.as_object_mut()) {
            map.insert("actor".into(), serde_json::json!(actor.sub));
            if let Some(name) = &actor.name {
                map.insert("actor_name".into(), serde_json::json!(name));
            }
        }
        payload.summary = summary;
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// Append the record of a control-plane change that applied at once, with no hold: the change as
    /// asked for, what applying it returned, and the operator session that asked. Written after the
    /// change has committed, because an audit append cannot run inside a store transaction. A failure
    /// here is returned rather than swallowed: the change stands and its record does not, so the
    /// caller has to hear about it (a hosted store is also quarantined by the failed upload; a local
    /// SQLite store is not).
    ///
    /// `title` is [`Self::describe_mutation`] read BEFORE the mutation was applied: a delete leaves
    /// nothing to name afterwards, and the applied event would record the raw id where the held
    /// event for the same change records the name.
    pub fn audit_applied_mutation(
        &self,
        capability: &str,
        mutation: &crate::policy_guard::Mutation,
        title: &str,
        applied: &serde_json::Value,
        op: &Session,
        remote: bool,
    ) -> Result<(), GatewayError> {
        let mut payload = AuditPayload::new(capability.to_string(), "control-plane".to_string(), "allow");
        payload.user_id = op.user_id.clone();
        payload.agent_id = Some(op.agent_id.clone());
        payload.device_id = op.device_id.clone();
        payload.session_id = Some(op.id.clone());
        // A member chooses what a change carries (a deny list can be thousands of entries), and the chain keeps every event resident, so what it records past a small size is the change's length and digest.
        payload.summary = serde_json::json!({
            "method": "applied",
            "remote": remote,
            "title": crate::audit_bound::cut_text(title),
            "mutation": crate::audit_bound::recorded(mutation),
            "applied": crate::audit_bound::recorded(applied),
            "actor": op.actor,
        });
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// Who approved, by name, for the events a resolution writes. See [`ApproverDetail`].
    ///
    /// `signers` lists only the signatures the quorum actually counted (the same live-key rule as
    /// [`live_people_count`]), and only when `with_signers`: a denial is one device's refusal, and
    /// listing the devices that had approved under it would name them as the ones who said no.
    fn approver_detail(
        &self,
        approval: &PendingApproval,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
        with_signers: bool,
    ) -> ApproverDetail {
        let name_of = |id: &str| {
            self.push
                .find_by_approver(id)
                .map(|d| d.name.trim().chars().take(APPROVER_NAME_MAX).collect::<String>())
                .filter(|n| !n.is_empty())
        };
        let (signers, people) = if with_signers {
            let keyring = self.approver_keyring_snapshot();
            let signers = approval
                .signatures
                .iter()
                .filter(|sig| {
                    keyring.trusted_key(&sig.approver).is_some_and(|k| key_fingerprint(k) == sig.key_fp)
                })
                .map(|sig| (sig.approver.clone(), name_of(&sig.approver)))
                .collect();
            let people = (!approval.signatures.is_empty())
                .then(|| live_people_count(&keyring, &approval.signatures));
            (signers, people)
        } else {
            (Vec::new(), None)
        };
        // A bearer resolution has no device to name, only the member the console said was acting.
        let (name, actor) = match method {
            "device_signed" => (approver.and_then(name_of), None),
            "bearer" => (actor.and_then(|a| a.name.clone()), actor.map(|a| a.sub.clone())),
            _ => (None, None),
        };
        ApproverDetail { name, actor, signers, people }
    }

    /// Write the floor override through to the selected backend. `None` means "no override" and is
    /// recorded as the *absence* of a value: the file is removed, and because the store has no
    /// delete, the store row is set to the empty string, which
    /// [`Self::load_persisted_keyring`] reads back as absent. Empty and missing must stay
    /// interchangeable, or a cleared override would come back as an unparseable trust-root setting.
    fn write_approval_floor(&self, floor: Option<ApprovalFloor>) -> Result<(), GatewayError> {
        match &self.keyring_persistence {
            KeyringPersistence::File { floor: path, .. } => {
                let res = match floor {
                    Some(f) => permaura_core::secret_file::replace_secret_file(path, f.as_str().as_bytes()),
                    None => match std::fs::remove_file(path) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        other => other,
                    },
                };
                res.map_err(|e| {
                    GatewayError::Internal(format!("failed to persist the approval floor: {e}"))
                })
            }
            KeyringPersistence::Store => {
                // No refresh-clock stamp: this path wrote the FLOOR and read nothing, so advancing
                // the deadline would leave the instance serving a keyring it has not re-read since,
                // and an operator toggling the floor is exactly the caller who would do that often.
                self.store
                    .put_meta(APPROVAL_FLOOR_META, floor.map(|f| f.as_str()).unwrap_or(""))?;
                Ok(())
            }
        }
    }

    /// Set (or clear) the explicit operator floor override and persist it. `None` returns the
    /// gateway to the enrolment-decides default. Lowering or clearing it is a trust-root control: the
    /// REST layer reaches that only from loopback, or on a hosted worker behind the owner-scoped
    /// step-up, and holds it for a trusted device's co-signature while one exists unless a recovery
    /// code or ticket is presented; raising it to `DeviceSigned` is fail-safe and reaches it from any
    /// operator. LOWERING it (to `Approve`) is what re-enables console approvals for `approve`-tier
    /// actions after a device is paired.
    ///
    /// A persistence failure is REPORTED, and the two directions repair themselves differently.
    ///
    /// A failed **lowering** used to log a warning and answer success. It never was: under
    /// [`KeyringPersistence::Store`] the next refresh within [`KEYRING_REFRESH_MS`] reloads the
    /// stored (stricter) value and the opt-down the operator was told had landed silently undoes
    /// itself, and on a hosted worker it takes another step-up ticket to try again, so the operator
    /// is left believing bearer approvals are open when they are about to close. The in-memory value
    /// is rolled back so this instance never serves an opt-down that did not persist, and the caller
    /// is told.
    ///
    /// A failed **raise or clear** could leave a stale looser value in the backend, which is the
    /// fail-OPEN direction, so the strictest value is forced in and installed in memory. Forcing
    /// `DeviceSigned` satisfies a raise (the requested state landed, so that is `Ok`) but not a
    /// clear, which asked for something else and gets the error.
    pub fn set_approval_floor(&self, floor: Option<ApprovalFloor>) -> Result<(), GatewayError> {
        let previous = *self.approval_floor.read().expect("approval floor lock not poisoned");
        *self.approval_floor.write().expect("approval floor lock not poisoned") = floor;
        let Err(e) = self.write_approval_floor(floor) else { return Ok(()) };
        if matches!(floor, Some(ApprovalFloor::Approve)) {
            *self.approval_floor.write().expect("approval floor lock not poisoned") = previous;
            tracing::error!(error = %e, "approval-floor opt-down did not persist; rolled back so nothing serves an unpersisted opt-down");
            return Err(e);
        }
        match self.write_approval_floor(Some(ApprovalFloor::DeviceSigned)) {
            Ok(()) => {
                *self.approval_floor.write().expect("approval floor lock not poisoned") =
                    Some(ApprovalFloor::DeviceSigned);
                tracing::error!(error = %e, "approval-floor persist failed; forced device_signed to fail safe");
                if matches!(floor, Some(ApprovalFloor::DeviceSigned)) {
                    return Ok(());
                }
            }
            Err(e2) => tracing::error!(error = %e2, orig = %e, "CRITICAL: could not force the device_signed floor after a tightening-persist failure; a stale looser floor may survive restart"),
        }
        Err(e)
    }

    /// Append an audit event for an approver-key enrolment attempt.
    ///
    /// Pairing has neither of the inputs the other two writers assume: there is no agent [`Session`]
    /// (the caller is an operator, or on a hosted worker an owner-scoped OAuth identity) and no
    /// connector [`Capability`], so it gets the synthetic action `permaura.approver.pair` against the
    /// `approver-keyring` resource. Every enrolment that gets past the authority check is recorded,
    /// refused ones included: on a hosted worker this log is the only place the trust-on-first-use
    /// enrolment is visible after the fact, and an attempt that was refused is exactly the event an
    /// owner needs to see.
    ///
    /// `authority` names what permitted the change (the loopback path, the owner-scoped step-up
    /// ticket, a device co-signature) and `detail` carries whatever the caller wants alongside it:
    /// the ticket `jti`, the co-signing approval id. The three base keys are written last so a
    /// caller's `detail` can never overwrite the record of who authorised the enrolment.
    ///
    /// `pubkey_b64` is `None` when this worker genuinely does not know which key the event concerns,
    /// and the `key_fp` field is then OMITTED rather than written. Hashing an empty string produces a
    /// perfectly well-formed fingerprint that identifies nothing, and a reader comparing it against
    /// the fingerprint on a ticket or a pairing notice has no way to tell it apart from a real one;
    /// an absent field says "unknown" and a fabricated one says something false.
    pub fn audit_approver_pairing(
        &self,
        decision: &str,
        approver_id: &str,
        pubkey_b64: Option<&str>,
        authority: &str,
        detail: serde_json::Value,
    ) -> Result<(), GatewayError> {
        let mut payload =
            AuditPayload::new("permaura.approver.pair", "approver-keyring", decision);
        let mut summary = match detail {
            serde_json::Value::Object(map) => map,
            serde_json::Value::Null => serde_json::Map::new(),
            other => {
                let mut map = serde_json::Map::new();
                map.insert("detail".into(), other);
                map
            }
        };
        summary.remove("key_fp");
        summary.insert("approver_id".into(), serde_json::json!(approver_id));
        if let Some(pubkey) = pubkey_b64 {
            summary.insert("key_fp".into(), serde_json::json!(key_fingerprint(pubkey)));
        }
        summary.insert("authority".into(), serde_json::json!(authority));
        payload.summary = serde_json::Value::Object(summary);
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// The audit record for a change to the approval floor that went through the guarded funnel: what it
    /// was, what it is now, and what authorised it, with the same evidence a keyring change records
    /// (the ticket, the re-authentication, the actor and the role it rested on, or the recovery code).
    /// Lowering the floor switches every device hold off, so it must be as reviewable as revoking the
    /// last key, which is the other half of the same recovery.
    pub fn audit_approval_floor(
        &self,
        from: Option<ApprovalFloor>,
        to: Option<ApprovalFloor>,
        authority: &str,
        detail: serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), GatewayError> {
        let mut payload = AuditPayload::new(APPROVAL_FLOOR_ACTION, "approval-floor", "allow");
        let mut summary = detail;
        // The STORED values: the effective floor reads `approve` for both an untouched gateway and an
        // explicit opt-down, so recording it made the one change that disarms every device hold read
        // as `approve` to `approve`.
        let stored = |f: Option<ApprovalFloor>| f.map_or("default", ApprovalFloor::as_str);
        summary.insert("from".into(), serde_json::json!(stored(from)));
        summary.insert("to".into(), serde_json::json!(stored(to)));
        summary.insert("effective".into(), serde_json::json!(self.approval_floor().as_str()));
        summary.insert("authority".into(), serde_json::json!(authority));
        payload.summary = serde_json::Value::Object(summary);
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// The audit record for the new-agent gate changing by default, with no operator choice behind it: the first device trusted on a gateway reachable from off the host turns it on (clearing a stored `false` no device holder confirmed, when there is one) and the last one revoked turns it off. Without it, nothing in the chain says why agents that used to land Approved now wait.
    pub fn audit_agent_gate_default(
        &self,
        from: bool,
        to: bool,
        cleared_stored_choice: bool,
        authority: &str,
    ) -> Result<(), GatewayError> {
        let reason = if cleared_stored_choice {
            "the stored choice to let new agents act without approval was made before any device was trusted, so the first device paired returns the gate to its default"
        } else if to {
            "a device is trusted on a gateway reachable from off the host, so a new agent waits for approval"
        } else {
            "no device is trusted, so a new agent is approved on consent again"
        };
        self.append_agent_gate_default(from, to, cleared_stored_choice, authority, reason)?;
        if let Err(e) = self.store.put_meta(crate::store::AGENT_GATE_DEFAULT_RECORDED_META, if to { "true" } else { "false" }) {
            tracing::warn!(error = %e, "could not note the new-agent gate default just recorded; the next start may record it again");
        }
        Ok(())
    }

    fn append_agent_gate_default(
        &self,
        from: bool,
        to: bool,
        cleared_stored_choice: bool,
        authority: &str,
        reason: &str,
    ) -> Result<(), GatewayError> {
        let mut payload = AuditPayload::new(AGENT_GATE_DEFAULT_ACTION, "agent-gate", "allow");
        payload.summary = serde_json::json!({
            "from": from,
            "to": to,
            "source": AgentGateSource::Default.as_str(),
            "cleared_stored_choice": cleared_stored_choice,
            "reason": reason,
            "authority": authority,
        });
        self.store.append_audit(payload)?;
        Ok(())
    }

    /// At start, mark when this gateway began recording who asked for a held change, once: the first start of such a build. A hold naming nobody from before then may be a member's, so it is no longer confirmable by any device.
    pub fn note_hold_requesters_recorded_since(&self) -> Result<(), GatewayError> {
        let key = crate::store::HOLD_REQUESTERS_RECORDED_SINCE_META;
        self.store.transaction(|store| {
            if store.get_meta(key)?.is_some_and(|v| !v.is_empty()) {
                return Ok(());
            }
            store.put_meta(key, &now_ms().to_string())
        })
    }

    /// Whether `pending` was held before this gateway recorded requesters. An unreadable boundary counts as before; a store that never marked one (only a test assembles a service with no start) has nothing from before it.
    fn held_before_requesters_were_recorded(&self, pending: &PendingApproval) -> bool {
        match self.store.get_meta(crate::store::HOLD_REQUESTERS_RECORDED_SINCE_META) {
            Ok(Some(since)) if !since.is_empty() => since.parse::<i64>().map_or(true, |since| pending.created_at < since),
            Ok(_) => false,
            Err(_) => true,
        }
    }

    /// Whether `approver` signs with a key bound to the gateway's owner (`PERMAURA_OWNER_SUB`). A gateway with no owner recorded has no such key. Read off the person the keyring bound the key to, never off an approver id of the form `user:<owner>`, which a pairing client could choose.
    pub(crate) fn is_the_owners_device(&self, keyring: &ApproverKeyring, approver: &str) -> bool {
        let Some(owner) = self.oauth.as_ref().and_then(|o| o.owner_sub()) else { return false };
        keyring.bound_to(approver, &owner)
    }

    /// At start, record the new-agent gate's default when it differs from the last one the chain recorded: a gateway that already trusted a device when it upgraded to a build where the gate defaults on, or a restart that gave a paired gateway a public URL or took it away. Nothing while the operator's stored choice or the environment decides. Returns whether it wrote a row.
    pub fn record_agent_gate_default_at_start(&self) -> Result<bool, GatewayError> {
        if self.require_agent_approval_source() != AgentGateSource::Default {
            return Ok(false);
        }
        let to = self.agent_gate_default();
        let key = crate::store::AGENT_GATE_DEFAULT_RECORDED_META;
        // Claimed in one unit, so the instances of a hosted worker starting together write one row between them.
        let claimed = self.store.transaction(|store| {
            let recorded = store.get_meta(key)?.filter(|v| !v.is_empty());
            if (recorded.as_deref() == Some("true")) == to {
                return Ok(None);
            }
            store.put_meta(key, if to { "true" } else { "false" })?;
            Ok(Some(recorded))
        })?;
        let Some(recorded) = claimed else { return Ok(false) };
        let (authority, reason) = match (&recorded, to) {
            (None, _) => (
                "upgrade",
                "an upgrade turned the gate on by default: this gateway is reachable from off the host and already trusts a device, so a new agent waits for approval",
            ),
            (Some(_), true) => (
                "restart",
                "this start made the gateway reachable from off the host while it trusts a device, so a new agent waits for approval",
            ),
            (Some(_), false) => (
                "restart",
                "this start left the gateway reachable from nowhere but its own host, so a new agent is approved on consent again",
            ),
        };
        if let Err(e) = self.append_agent_gate_default(!to, to, false, authority, reason) {
            let restore = recorded.as_deref().unwrap_or("");
            if let Err(undo) = self.store.put_meta(key, restore) {
                tracing::warn!(error = %undo, "could not undo the claim on a new-agent gate row that was not written");
            }
            return Err(e);
        }
        Ok(true)
    }

    /// The lock the broker-guard critical section holds so a classifier's store snapshot cannot
    /// shift before its mutation is applied (the classifier↔apply TOCTOU).
    pub fn control_plane_mutex(&self) -> &tokio::sync::Mutex<()> {
        &self.control_plane_lock
    }

    /// Room in the JSON pool for the tree a rendering of `approvals` walks, kept while they are rendered: the largest of their trees, since a listing renders one at a time and drops each tree before the next. A row over what a rendering may build renders as too large to show without a tree and reserves nothing ([`crate::approval_display::tree_bytes`]).
    /// No room within the pool wait is a 429 "memory", as for every other tree of untrusted bytes; nothing is rendered uncharged.
    pub async fn display_room<'a>(&self, approvals: impl IntoIterator<Item = &'a PendingApproval>) -> Result<MemoryCharge, GatewayError> {
        let largest = approvals.into_iter().filter_map(crate::approval_display::tree_bytes).max().unwrap_or(0);
        self.memory.pool().reserve(largest, self.memory.wait()).await.map_err(crate::memory::pool_refusal)
    }

    /// [`Self::display_room`] taken only if the pool has room at once, for a settled row whose rendering is only read back: `None` is answered without the rendering, never with a wait or a 429 for a decision already recorded.
    pub fn display_room_now<'a>(&self, approvals: impl IntoIterator<Item = &'a PendingApproval>) -> Option<MemoryCharge> {
        let largest = approvals.into_iter().filter_map(crate::approval_display::tree_bytes).max().unwrap_or(0);
        self.memory.pool().try_reserve(largest)
    }

    /// [`Self::display_room`] for the rendering [`Self::verify_signed_approval`] checks a device's approve against (step 7b): the held row's, when `result` approves over a display digest and the row is still pending, and none otherwise, since nothing is rendered then.
    /// A row whose approval this process is already running, which a retried tap or another device's signature can name, is rendered only within room the pool has at once, and is otherwise the pool's 429 "memory" without a wait: its approval's own reservation is what a wait would queue behind, holding every agent call queued after it.
    pub async fn display_room_for_signed(&self, result: &ApprovalResult) -> Result<MemoryCharge, GatewayError> {
        if !result.approve || result.display_digest.is_none() {
            return Ok(MemoryCharge::none());
        }
        match self.store.get_approval(&result.approval_id) {
            Ok(Some(pending)) if pending.status == "pending" && self.executions.is_resolving(&pending.id) => {
                let tree = crate::approval_display::tree_bytes(&pending).unwrap_or(0);
                self.memory.pool().reserve(tree, std::time::Duration::ZERO).await.map_err(crate::memory::pool_refusal)
            }
            Ok(Some(pending)) if pending.status == "pending" => self.display_room([&pending]).await,
            _ => Ok(MemoryCharge::none()),
        }
    }

    /// The single verifier for a device-signed approval, shared by the relay Frame path and the REST
    /// `POST /v1/approvals` path so there is exactly one place the trust rules live. It verifies the
    /// ed25519 signature against the worker-LOCAL trusted key for `result.approver` (never the
    /// body-carried pubkey), checks decision freshness, that the held approval exists, is pending and
    /// unexpired, re-binds `request_hash` to the exact held call, and refuses self-approval. It does
    /// NOT run the held call; the caller does that on [`SignedApprovalOutcome::Verified`] via
    /// [`Self::resolve_approval`], keeping this method synchronous (no lock held across an await).
    pub fn verify_signed_approval(
        &self,
        keyring: &ApproverKeyring,
        result: &ApprovalResult,
    ) -> SignedApprovalOutcome {
        use SignedApprovalOutcome::{AlreadyResolved, AwaitingSignatures, Refused, Verified};
        // 1. The approver must be enrolled locally (and not revoked); resolve ITS trusted key.
        let trusted = match keyring.trusted_key(&result.approver) {
            Some(k) => k,
            None => {
                return Refused(format!(
                    "approval from unknown/revoked approver '{}'",
                    result.approver
                ))
            }
        };
        // 1b. A device that came back with a restored snapshot cannot approve until its owner
        //     confirms it. Here rather than in `resolve_approval`, because this is where trust in
        //     a key is established: a device whose pairing survived only because the generation
        //     that revoked it was thrown away must not be able to authorise anything, and least of
        //     all its own reinstatement.
        //     A record this gateway cannot read refuses too: it is the only answer that does not
        //     rest on a guess about whether this device was ever confirmed.
        match self.reconciliation() {
            Ok(Some(review)) if review.blocks(crate::reconcile::ReviewKind::Device, &result.approver) => {
                return Refused(format!(
                    "approver '{}' came back with a restored snapshot and its owner has not confirmed it yet",
                    result.approver
                ))
            }
            Err(e) => {
                return Refused(format!(
                    "this gateway cannot tell whether approver '{}' is awaiting review after a restore: {e}",
                    result.approver
                ))
            }
            _ => {}
        }
        // 2. Verify the device signature over the canonical preimage against THAT key. A v2 signature
        //    names the gateway it was made for and must name this one; a v1 signature names none, so
        //    it is taken only while this gateway still accepts v1 from this approver.
        if let Some(why) =
            self.device_signature_version_refusal(&result.approver, result.audience.as_deref())
        {
            return Refused(format!("approval '{}': {why}", result.approval_id));
        }
        if let Some(why) =
            self.display_binding_refusal(&result.approver, result.approve, result.display_digest.as_deref())
        {
            return Refused(format!("approval '{}': {why}", result.approval_id));
        }
        let preimage = match (result.display_digest.as_deref(), result.audience.as_deref()) {
            (Some(display_digest), audience) => approval_result_preimage_v3(
                audience.unwrap_or(""),
                &result.job_id,
                &result.approval_id,
                result.approve,
                &result.request_hash,
                display_digest,
                &result.approver,
                result.decided_at,
            ),
            (None, Some(audience)) => approval_result_preimage_v2(
                audience,
                &result.job_id,
                &result.approval_id,
                result.approve,
                &result.request_hash,
                &result.approver,
                result.decided_at,
            ),
            (None, None) => approval_result_preimage(
                &result.job_id,
                &result.approval_id,
                result.approve,
                &result.request_hash,
                &result.approver,
                result.decided_at,
            ),
        };
        if verify_sig(trusted, &preimage, &result.device_sig).is_err() {
            return Refused(format!("approval '{}' signature did not verify", result.approval_id));
        }
        if result.audience.is_some() {
            self.note_v2_signer(&result.approver);
        }
        if result.display_digest.is_some() {
            self.note_display_signer(&result.approver);
        }
        // 3. Freshness: bound how late a captured-but-still-pending signed decision can be replayed.
        if (now_ms() - result.decided_at).abs() > DECISION_FRESHNESS_MS {
            return Refused(format!("approval '{}' decision is stale", result.approval_id));
        }
        // 4. The held approval must exist.
        let pending = match self.store.get_approval(&result.approval_id) {
            Ok(Some(p)) => p,
            _ => return Refused(format!("approval '{}' not found", result.approval_id)),
        };
        // 5. Idempotent: already resolved → never re-run; surface its terminal state.
        if pending.status != "pending" {
            return AlreadyResolved(pending);
        }
        // 6. Unexpired, against the deadline CAPTURED on the row, which is the one the approver was
        //    shown. Recomputed from the TTL constant this refused on a deadline no client had ever
        //    been told about.
        if pending.is_expired(now_ms()) {
            if pending.is_control_plane_hold() {
                return Refused(format!(
                    "approval '{}' expired before anyone confirmed it; ask for the change again",
                    result.approval_id
                ));
            }
            return Refused(format!("approval '{}' expired", result.approval_id));
        }
        // 7. Bind the signed decision to the exact held call by recomputing the hash from the stored
        //    capability + params; a broker/CP that altered params can't get a signature over one
        //    request_hash executed against a different call.
        if held_request_hash(&pending.capability, &pending.params) != result.request_hash {
            return Refused(format!("approval '{}' request_hash mismatch", result.approval_id));
        }
        // 7b. Bind an approve to what the approver SAW: the device signed the digest of the full
        //     rendering it put on screen, which must be this held call's, recomputed here, and a call too
        //     large to render whole cannot be approved at all. A denial is not checked: it runs nothing,
        //     and refusing it would only keep alive a call somebody has said no to. The callers hold room
        //     in the pool for the rendering's tree (`display_room_for_signed`).
        if let (Some(shown), true) = (result.display_digest.as_deref(), result.approve) {
            let inputs = crate::approval_display::RenderInputs::for_approval(self.store.as_ref(), &pending);
            match crate::approval_display::full_digest(&pending, &inputs) {
                None => {
                    return Refused(format!(
                        "approval '{}': this call's parameters are too large to show in full, so it can only be denied; change the policy rung for this action to allow such calls",
                        result.approval_id
                    ))
                }
                Some(own) if own != shown => {
                    return Refused(format!(
                        "approval '{}': the parameters shown on the approving device are not the ones this call would run with",
                        result.approval_id
                    ))
                }
                Some(_) => {}
            }
        }
        // 8. Separation of duty: the approver must not be the principal that requested the held call.
        //    Checked for EVERY signer, so a two-person rule cannot be half-satisfied by the caller.
        if let Ok(Some(session)) = self.store.get_session(&pending.session_id) {
            let is_self = session
                .user_id
                .as_deref()
                .is_some_and(|u| result.approver == format!("user:{u}"))
                || session
                    .device_id
                    .as_deref()
                    .is_some_and(|d| result.approver == format!("device:{d}"))
                || result.approver == format!("agent:{}", session.agent_id)
                || result.approver == session.agent_id;
            if is_self {
                return Refused(format!(
                    "self-approval refused: approver '{}' is the requesting principal",
                    result.approver
                ));
            }
        }

        // 9. A DENIAL from any single approver ends it immediately. Two-person approval means two
        //    people must agree to proceed; it never means one person can be outvoted into
        //    proceeding. One veto is enough, and waiting for a quorum of denials would be absurd.
        if !result.approve {
            return Verified;
        }

        // 10. Quorum. Record this signature and decide whether it was the last one needed. The
        //     whole record-then-count step runs under a lock so that when two people tap approve
        //     at the same moment exactly ONE of them observes the transition to complete. This lock
        //     preserves signature collection within this service; resolve_approval's durable claim
        //     separately prevents concurrent resolutions from executing the action twice.
        //     The lock is inside one store unit of work, so the row is written under it and uploaded
        //     after it is released (see `locked_store_section`).
        let recorded = self.locked_store_section(&self.signature_lock, || {
            // Re-read inside the lock: another signer may have completed the quorum and resolved the
            // approval between step 5 and here.
            let mut pending = match self.store.get_approval(&result.approval_id) {
                Ok(Some(p)) => p,
                _ => return Ok(Refused(format!("approval '{}' not found", result.approval_id))),
            };
            if pending.status != "pending" {
                return Ok(AlreadyResolved(pending));
            }
            let required = pending.required_signatures.max(1);

            // 10a. Separation of duty for a held control-plane change or export, which has no requesting
            //      session for step 8 to read: it names who asked, and a device of theirs does not confirm
            //      it alone while a device more provably someone else's is trusted. Above a quorum of one
            //      their device may be one of the signers, because the quorum counts distinct people and
            //      so cannot complete without someone else.
            //      What it takes is also never less than when it was asked for: revoking the devices that
            //      were independent of the requester leaves the hold unconfirmable rather than theirs.
            //      A device bound to the gateway's owner satisfies all of it, whoever asked: the owner can always make a change with their own signed device. Nobody else is exempt.
            let owners_device = self.is_the_owners_device(keyring, &result.approver);
            if pending.session_id.is_empty() && required == 1 && pending.requested_by.is_none() && self.held_before_requesters_were_recorded(&pending) && !owners_device {
                return Ok(Refused(format!(
                    "approval refused: this change was held before this gateway recorded who asked for it, so only a device paired to the gateway's owner can confirm it, and approver '{}' is not one; deny it and ask for the change again",
                    result.approver
                )));
            }
            if pending.session_id.is_empty() && required == 1 && !owners_device {
                if let Some(requester) = &pending.requested_by {
                    use crate::relay::approver::Independence;
                    let signer = keyring.independence(&result.approver, requester);
                    if signer < keyring.most_independent(requester) {
                        return Ok(Refused(match signer {
                            Some(Independence::Requester) => format!(
                                "self-approval refused: approver '{}' belongs to the person who asked for this change; a device paired to someone else has to confirm it",
                                result.approver
                            ),
                            _ => format!(
                                "approval refused: approver '{}' is paired to nobody in particular, so it cannot show it is not the requester's; a device paired to someone other than the person who asked has to confirm it",
                                result.approver
                            ),
                        }));
                    }
                    if signer < requester.required_independence {
                        let was = match requester.required_independence {
                            Some(Independence::Independent) => "a device paired to someone other than the person who asked",
                            _ => "a device paired to nobody in particular",
                        };
                        return Ok(Refused(match signer {
                            Some(Independence::Requester) => format!(
                                "self-approval refused: approver '{}' belongs to the person who asked for this; when it was asked for, {was} was trusted to confirm it, and that device has since been revoked, which does not make the requester's own device enough. Ask for it again: a new request is held for whoever can confirm it now",
                                result.approver
                            ),
                            _ => format!(
                                "approval refused: approver '{}' is paired to nobody in particular; when this was asked for, {was} was trusted to confirm it, and that device has since been revoked. Ask for it again: a new request is held for whoever can confirm it now",
                                result.approver
                            ),
                        }));
                    }
                }
            }

            // Distinctness on BOTH the approver id and the key it verified against. The id alone is
            // not enough: one physical device paired twice under two names would otherwise satisfy a
            // two-person rule by itself, which is the entire thing the rule exists to prevent.
            let key_fp = key_fingerprint(trusted);
            if let Some(existing) = pending
                .signatures
                .iter()
                .find(|s| s.approver == result.approver || s.key_fp == key_fp)
            {
                // Idempotent, not an error: a retried delivery of the same signature must not count
                // twice, and must not look like a failure to the device that sent it.
                let collected = live_people_count(keyring, &pending.signatures);
                tracing::debug!(
                    approval = %result.approval_id,
                    approver = %result.approver,
                    already = %existing.approver,
                    "duplicate signature ignored (same device already signed)"
                );
                // The saved signatures can come to speak for more people than when they were counted, once a key paired before keys named a person is bound; nothing else would ever complete such a hold.
                if collected >= required {
                    return Ok(Verified);
                }
                return Ok(AwaitingSignatures {
                    approval: pending,
                    collected,
                    required,
                });
            }

            pending.signatures.push(crate::store::CollectedSignature {
                approver: result.approver.clone(),
                key_fp,
                decided_at: result.decided_at,
            });
            // Count the PEOPLE whose devices are STILL trusted with the SAME key. Revoking a stolen
            // phone has to take back the half-approval it already gave, a device that re-paired with a
            // fresh key is not the device that signed, and a second device of the same person is not a
            // second person.
            let collected = live_people_count(keyring, &pending.signatures);
            self.store.put_approval(pending.clone())?;
            Ok(if collected >= required {
                Verified
            } else {
                AwaitingSignatures {
                    approval: pending,
                    collected,
                    required,
                }
            })
        });
        // Fail closed: if the signature could not be recorded we cannot know the quorum, and
        // running on an uncounted signature is exactly the failure the rule guards against.
        recorded.unwrap_or_else(|e| {
            Refused(format!(
                "approval '{}' signature could not be recorded: {e}",
                result.approval_id
            ))
        })
    }

    /// Load the push registry a previous run persisted, so a restart does not silence every device.
    ///
    /// A read failure is a warning and an empty registry, not a refusal: this drives notifications
    /// and nothing else, and a gateway that will not start because it could not read a phone's push
    /// token is worse than one that announces nothing until the phone re-enrols.
    ///
    /// `is_sender` is whether this gateway is still the party that sends approval notifications. It
    /// is, unless it announces to a control plane, which then sends, from a server that can hold an
    /// Expo credential. This is the one decision behind the push-token rule: the gateway keeps a device's push
    /// address only for as long as it is the one using it.
    fn restored_push_registry(store: &Arc<dyn Store>, is_sender: bool) -> Arc<crate::push::DeviceRegistry> {
        let registry = crate::push::DeviceRegistry::new(is_sender);
        match store.get_meta(crate::push::DEVICES_META) {
            Ok(Some(json)) if !json.trim().is_empty() => {
                // A snapshot written before this gateway started announcing still carries addresses.
                // Rewriting the row here is what stops one surviving another restart; dropping it
                // in memory alone would leave the store holding it for ever.
                if registry.restore(&json) {
                    match registry.snapshot() {
                        Ok(stripped) => {
                            if let Err(e) = store.put_meta(crate::push::DEVICES_META, &stripped) {
                                tracing::warn!(error = %e, "could not rewrite the push registry without its addresses");
                            } else {
                                tracing::info!(
                                    "dropped the stored push addresses: the control plane is the sender now"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "could not encode the stripped push registry"),
                    }
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "could not read the persisted push registry"),
        }
        Arc::new(registry)
    }

    /// Mirror the registry to `gateway_meta` after a change.
    ///
    /// Best effort and logged. Failing the enrolment because the mirror could not be written would
    /// leave a device the gateway is notifying but the console cannot show, which is a worse kind of
    /// disagreement than one this run repairs on its next write.
    fn persist_push_registry(&self) {
        match self.push.snapshot() {
            Ok(json) => {
                if let Err(e) = self.store.put_meta(crate::push::DEVICES_META, &json) {
                    tracing::warn!(error = %e, "could not persist the push registry");
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not encode the push registry"),
        }
    }

    /// Every workspace link this gateway announces to right now.
    pub fn announce_links(&self) -> Vec<crate::announce::Config> {
        self.announcer.links()
    }

    /// Where permaura.com's requests to re-seal a link are recorded, for the re-seal task.
    pub fn reseal_requests(&self) -> Arc<crate::announce::ResealRequests> {
        self.announcer.reseal_requests()
    }

    /// The pairings this machine has completed since boot, each of which may have handed permaura.com `operator.token`.
    pub fn pairings(&self) -> Arc<crate::announce::Pairings> {
        self.announcer.pairings()
    }

    /// Replace the links while running. Holding any link hands notification to the control plane, so
    /// the push addresses this gateway held as the sender are dropped and the stored copy rewritten
    /// in the same call; holding none hands the job back.
    pub fn set_announce(&self, links: Vec<crate::announce::Config>) {
        let is_sender = links.is_empty();
        self.announcer.set(links);
        if self.push.set_holds_push_tokens(is_sender) {
            self.persist_push_registry();
            tracing::info!("dropped the stored push addresses: the control plane is the sender now");
        }
    }

    /// Whether this gateway keeps device push addresses, which it does only while it is the sender.
    pub fn holds_push_tokens(&self) -> bool {
        self.push.holds_push_tokens()
    }

    /// Register a phone's Expo push token so approval notifications can reach it
    /// (`POST /v1/devices/push-token`). Best-effort; see [`crate::push`].
    pub fn register_push_token(&self, token: String) {
        self.push.register(token);
        self.persist_push_registry();
    }

    /// Enroll (or replace) an approval device, the operator's phone, with its push token and the
    /// approver key it would sign with (recorded for display; not yet trusted, see push docs).
    pub fn enroll_device(&self, device: crate::push::Device) {
        self.push.upsert(device);
        self.persist_push_registry();
    }

    /// Every enrolled device, for the console's "Enrolled devices" list.
    pub fn list_devices(&self) -> Vec<crate::push::Device> {
        self.push.list()
    }

    /// Whether a non-revoked device already signs as `approver_id`.
    pub fn device_registered_for_approver(&self, approver_id: &str) -> bool {
        self.push.has_approver(approver_id)
    }

    /// Revoke an enrolled device (a lost/rotated phone). Returns false if unknown.
    pub fn revoke_device(&self, id: &str) -> bool {
        let revoked = self.push.revoke(id);
        if revoked {
            self.persist_push_registry();
        }
        revoked
    }

    /// Record last-use, at most once a minute per session. `authenticate` is on the invoke hot path,
    /// so a store write per request would be a real cost (on a hosted worker especially, where it
    /// forces a snapshot upload) for a field nothing reads synchronously. Best-effort by design:
    /// failing to note a timestamp must never fail an otherwise valid request.
    ///
    /// `session` is what authentication read, and may be stale by now: an operator can revoke, delete
    /// or replace the row in between. So this never writes it back. [`Store::touch_session`] changes
    /// only the activity fields of the row as it stands, and does nothing to one that is no longer live.
    fn touch_session(&self, session: &Session, now: i64) {
        self.touch_session_sliding(session, true, now)
    }

    /// [`Self::touch_session`], extending an agent session's expiry only when `slides`: a bearer an older gateway minted as a 64-bit enrolment code keeps the expiry it has ([`is_short_enrolment_code`]).
    fn touch_session_sliding(&self, session: &Session, slides: bool, now: i64) {
        const TOUCH_INTERVAL_MS: i64 = 60_000;
        if matches!(session.last_used_at, Some(prev) if now - prev < TOUCH_INTERVAL_MS) {
            return;
        }
        // Sliding, so the cap measures idleness rather than age: an agent in daily use would otherwise
        // stop working thirty days after enrolment for no reason its owner could see. Agents only.
        // Operator sessions are rotated with overlap instead.
        let extend_expiry_to = (session.role == SessionRole::Agent && slides).then_some(now + crate::store::AGENT_SESSION_TTL_MS);
        let _ = self.store.touch_session(&session.id, &session.token, now, extend_expiry_to);
    }

    /// Why a bearer that opened `session` through `POST /v1/sessions`, or one that opened that, no longer stands behind it, or `None` while every opener does.
    ///
    /// Read at every request rather than cascaded when an opener ends, so revoking a bearer ends what it opened whichever route revoked it, and a session opened or written after a rotation read the session list still ends with its opener.
    fn opener_lapse(&self, session: &Session, now: i64) -> Result<Option<&'static str>, GatewayError> {
        const MAX_DEPTH: usize = 16;
        let mut next = session.opened_by.clone();
        for _ in 0..MAX_DEPTH {
            let Some(id) = next else { return Ok(None) };
            next = match self.store.get_session(&id)? {
                None => return Ok(Some("the session that opened it no longer exists")),
                Some(opener) if opener.revoked => return Ok(Some("the session that opened it has been revoked")),
                Some(opener) if opener.is_expired(now) => return Ok(Some("the session that opened it has expired")),
                Some(opener) => opener.opened_by,
            };
        }
        Ok(Some("it was opened through too many sessions to trace"))
    }

    /// Resolve and validate the session behind a bearer token. A revoked session is
    /// treated as unauthorized, and so is one whose opener has ended (see [`Self::opener_lapse`]).
    ///
    /// If the bearer matches no session, it may be a one-time **enrolment code used as a
    /// bootstrap bearer**, the path that makes a real MCP client (Claude Desktop via the
    /// stdio bridge, configured with `Authorization: Bearer ENRL-…`) work without a custom
    /// enrol handshake. We redeem the code once and mint a **Pending, Agent-role** session
    /// whose token *is* the code, so the same bearer keeps resolving to it. The agent cannot
    /// invoke anything until an operator approves it, and cannot drive the console (Agent
    /// role), so a leaked code still grants nothing on its own.
    pub fn authenticate(&self, token: &str) -> Result<Session, GatewayError> {
        // An empty bearer names nobody, and a stored row with an empty token must never be one it finds.
        if token.is_empty() {
            return Err(GatewayError::Unauthorized("empty bearer token".into()));
        }
        if let Some(session) = self.store.session_by_token(token)? {
            if session.revoked {
                return Err(GatewayError::Unauthorized("session has been revoked".into()));
            }
            let now = now_ms();
            // Ahead of the expiry check, since the pause holds an agent's clock still (`settle_agent_session_clock_at_start`): only a session that had run out before agents were paused is told it has expired. Ahead of the touch too, so a refusal slides nothing.
            if self.held_by_the_agent_pause(&session, now) {
                self.refuse_if_agents_paused()?;
            }
            if session.is_expired(now) {
                return Err(GatewayError::Unauthorized("session has expired".into()));
            }
            if let Some(why) = self.opener_lapse(&session, now)? {
                return Err(GatewayError::Unauthorized(why.into()));
            }
            self.touch_session_sliding(&session, !is_short_enrolment_code(token), now);
            return Ok(session);
        }
        // A permaura.com-issued access-token JWT (the remote/OAuth path). Validated offline against the AS JWKS; a token carrying the `mcp` scope means the user consented at the AS to an agent; a new agent lands Approved unless the new-agent gate is on, in which case it waits Pending for an operator. Grants still govern capabilities. A token consented for identity only is refused in `session_from_jwt`.
        if let Some(oauth) = &self.oauth {
            if token.matches('.').count() == 2 {
                let now_secs = now_ms() / 1000;
                return match oauth.verify(token, now_secs) {
                    // The console, acting as the operator, rather than an agent acting on their
                    // behalf. A hosted gateway has no other way in: session-open is loopback-only and
                    // PERMAURA_HOSTED closes the credential-free operator plane, so without this the
                    // control plane is unreachable for the very deployment mode that needs it most.
                    // Safe because `verify` has already bound the token to this gateway's audience AND
                    // to `PERMAURA_OWNER_SUB`, and the operator scope cannot be obtained through the
                    // authorize flow, only minted server-side by the console.
                    Ok(claims) if claims.is_operator() => Ok(self.operator_session_from_jwt(&claims)),
                    Ok(claims) => self.session_from_jwt(claims),
                    // A verify failure while the RS holds no keys yet is the JWKS fetch still in
                    // flight, not a bad bearer: on a cold worker (a fresh provision, or one just
                    // scaled up from zero) the first authenticated request can land before
                    // permaura.com's keys do. Answer 503-retryable so the caller tries again once
                    // they arrive, rather than the 401 that reads as an operator token to re-pair.
                    Err(_) if !oauth.verifier_ready() && !oauth.is_withdrawn() => Err(GatewayError::VerifierWarming(
                        "signing keys not fetched yet; retry shortly".into(),
                    )),
                    Err(reason) => Err(GatewayError::Unauthorized(format!("invalid token: {reason}"))),
                };
            }
        }
        // Last, because trying a code is a store read and redeeming one a write. The hosted console
        // presents a JWT on every request, and trying it as a code first meant one store write per read,
        // which during a storage outage turned every console read into a failure.
        // A paused worker redeems nothing, and the agent behind the code is not enrolled yet.
        if self.agents_paused() && self.store.enrolment_code_redeemable(token, now_ms())? {
            self.refuse_enrolment_if_agents_paused()?;
        }
        if let Some(session) = self.bootstrap_from_enrolment_code(token)? {
            if session.role == SessionRole::Agent {
                self.refuse_if_agents_paused()?;
            }
            return Ok(session);
        }
        Err(GatewayError::Unauthorized(
            "unknown or missing session token".into(),
        ))
    }

    /// Whether this run has agents paused and `session` is an agent's that was live when the pause began, so its expiry is held still until the resume moves it.
    /// Whether a stored session's bearer is still one this gateway accepts, by the rule [`Self::bearer_is_live`] applies: not revoked, and not expired unless the agent pause is holding its clock.
    pub(crate) fn stored_session_is_live(&self, session: &Session, now: i64) -> bool {
        !session.revoked && (!session.is_expired(now) || self.held_by_the_agent_pause(session, now))
    }

    fn held_by_the_agent_pause(&self, session: &Session, now: i64) -> bool {
        if session.role != SessionRole::Agent || !self.agents_paused() {
            return false;
        }
        let since = match crate::store::agents_paused_since(self.store.as_ref()) {
            Ok(since) => since.unwrap_or(now),
            Err(_) => i64::MIN,
        };
        !matches!(session.expires_at, Some(expiry) if expiry <= since)
    }

    /// Whether `token` names a live session or verifies as a token minted for this gateway, with none of
    /// [`Self::authenticate`]'s side effects: no session touch, no agent registration, no enrolment-code
    /// redemption. Admission control asks it before charging the worker-wide bucket, so a stranger with
    /// an invented bearer cannot spend the execution budget of the agents that hold real ones.
    pub fn bearer_is_live(&self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        if let Ok(Some(session)) = self.store.session_by_token(token) {
            let now = now_ms();
            return !session.revoked
                && (!session.is_expired(now) || self.held_by_the_agent_pause(&session, now))
                && matches!(self.opener_lapse(&session, now), Ok(None));
        }
        if token.matches('.').count() == 2 {
            return match &self.oauth {
                Some(oauth) => match oauth.verify(token, now_ms() / 1000) {
                    Ok(claims) => {
                        claims.is_operator()
                            || (claims.is_agent() && !self.oauth_agent_revoked(&oauth_agent_id(&claims)).unwrap_or(true))
                    }
                    Err(_) => false,
                },
                None => false,
            };
        }
        // An enrolment code not yet redeemed is an agent's first call, the one that redeems it. Counted against a bucket of its own, keyed by a code a stranger does not hold, rather than the one every unresolvable bearer shares, where a stranger's junk kept that call at 429 until the code expired. A read, never the redemption.
        self.store.enrolment_code_redeemable(token, now_ms()).unwrap_or(false)
    }

    /// Whether `token` is a permaura.com token of this gateway's own caller that has merely expired, with no side effects: see [`crate::oauth::OAuthRs::lapsed`]. Admission control answers it with a 401 ahead of every bucket, so a stranger's junk cannot withhold the refusal that makes the agent refresh. False on a gateway with no resource server, where no such token exists.
    pub fn bearer_lapsed(&self, token: &str) -> bool {
        match &self.oauth {
            Some(oauth) if token.matches('.').count() == 2 => oauth.lapsed(token, now_ms() / 1000),
            _ => false,
        }
    }

    /// Whether the owner revoked this OAuth agent's session while keeping the agent.
    ///
    /// The JWT is the credential and it never names the stored row, so the row's `revoked` flag is the
    /// only place that decision is recorded, and it has to be read on every request or revoking does
    /// nothing: the client keeps calling with the token it holds and refreshes it when it lapses. A
    /// revoked row with no agent behind it is a removal instead, which [`Self::session_from_jwt`] turns
    /// into a fresh Pending agent rather than a refusal.
    fn oauth_agent_revoked(&self, agent_id: &str) -> Result<bool, GatewayError> {
        let revoked = self.store.get_session(&oauth_session_id(agent_id))?.is_some_and(|s| s.revoked);
        Ok(revoked && self.store.get_agent(agent_id)?.is_some())
    }

    /// The OAuth Resource Server, if the gateway has a public URL (used by the metadata routes).
    pub fn oauth(&self) -> Option<&Arc<crate::oauth::OAuthRs>> {
        self.oauth.as_ref()
    }

    /// The resource server while it still takes tokens: what an answer may advertise (a ticket route, a sign-in, a public MCP URL). Once `permaura remote disable` withdraws it, [`Self::oauth`] still returns it for the gates that must keep refusing, and this returns nothing.
    pub fn live_oauth(&self) -> Option<&Arc<crate::oauth::OAuthRs>> {
        self.oauth.as_ref().filter(|o| !o.is_withdrawn())
    }

    /// Move the operator this gateway accepts tokens for to `sub`, the owner permaura.com named at a check-in, and say whether anything moved.
    ///
    /// After an ownership change permaura.com mints every console, phone and agent token for the new owner, and a headless gateway pinned to the old one refused them all until someone re-ran `permaura remote enable` on the machine. The check-in carries the link's announce credential and the answer names the owner; this follows it, so the binding moves on permaura.com's word over HTTPS. Nothing moves on a gateway with no resource server (there is no pin to move), or one `permaura remote disable` withdrew (nor is the owner written back into the config file it cleared), when `sub` is already the owner, when it is not shaped like an account id, or when `settable` is false because the app that supervises this gateway set `PERMAURA_OWNER_SUB` (it moves the binding itself). A move is audited, and written to `config_path` when there is one so it survives a restart, with `replaces_env`, the environment's own `PERMAURA_OWNER_SUB`, beside it so the written owner outranks that value at boot.
    pub fn repin_owner(&self, sub: &str, settable: bool, config_path: Option<&std::path::Path>, replaces_env: Option<&str>) -> Result<bool, GatewayError> {
        static ONE_MOVE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let Some(oauth) = self.oauth.as_ref().filter(|o| !o.is_withdrawn()) else { return Ok(false) };
        let sub = sub.trim();
        if !owner_sub_well_formed(sub) {
            tracing::warn!("permaura.com named an owner for this gateway that is not shaped like an account id; the binding stays where it is");
            return Ok(false);
        }
        let _moving = ONE_MOVE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        let from = oauth.owner_sub();
        if from.as_deref() == Some(sub) {
            return Ok(false);
        }
        if !settable {
            tracing::warn!("permaura.com says this gateway's organization has a new owner, but the app that supervises this gateway sets PERMAURA_OWNER_SUB, so the binding is not moved here; the app moves it and relaunches the gateway when it next hears from permaura.com");
            return Ok(false);
        }
        let mut payload = AuditPayload::new(OWNER_REPIN_ACTION, "owner-binding", "allow");
        payload.summary = serde_json::json!({
            "from": from,
            "to": sub,
            "source": "checkin",
            "reason": "permaura.com named the organization's current owner in the answer to this gateway's check-in",
        });
        // Recorded before the binding moves: a move the audit could not record does not happen, and the next check-in tries it again, rather than one that holds unaudited until a restart reverts it.
        self.store.append_audit(payload)?;
        oauth.repin_owner(sub);
        if let Some(path) = config_path {
            if let Err(e) = crate::config::write_owner_sub(path, sub, replaces_env) {
                tracing::warn!(path = %path.display(), "the new owner binding could not be written, so the next restart returns to the old one: {e}");
            } else if replaces_env.is_some_and(|env| env.trim() != sub) {
                tracing::warn!(path = %path.display(), "PERMAURA_OWNER_SUB in this gateway's environment still names the previous owner; the new owner is kept in the config file and outranks it at restart while it says exactly that. Set PERMAURA_OWNER_SUB to the new owner where it is set (for a VPS, /etc/permaura/gateway.env)");
            }
        }
        tracing::info!(from_bound = from.is_some(), "the organization's owner changed; this gateway now accepts the new owner's tokens");
        Ok(true)
    }

    /// Build an **operator** session for a console-minted, owner-bound JWT.
    ///
    /// Deliberately NOT persisted and NOT registered as an agent. The token is already short-lived and
    /// re-verified on every request, so a stored row would add a revocation surface without adding any
    /// authority, and listing the console as an "agent" would pollute the very agent list the
    /// operator uses to decide what to trust. The id is derived from the subject so audit entries from
    /// one operator collate.
    fn operator_session_from_jwt(&self, claims: &crate::oauth::VerifiedClaims) -> Session {
        let now = now_ms();
        Session {
            class: Default::default(),
            opened_by: None,
            id: format!("sess_oauth_op_{}", claims.sub),
            agent_id: format!("operator:{}", claims.sub),
            user_id: Some(claims.sub.clone()),
            device_id: None,
            token: String::new(), // never replayed: the bearer is the JWT the caller already holds
            role: SessionRole::Operator,
            created_at: now,
            revoked: false,
            // Authority ends with the token itself, which the AS mints short-lived; there is no stored
            // session to outlive it.
            expires_at: None,
            last_used_at: Some(now),
            actor: claims.actor.clone(),
        }
    }

    /// Build a Session for an agent authenticated by a valid permaura.com JWT. Upserts the agent and
    /// a stable session so the console shows it and any held approvals can be resolved later.
    /// Idempotent across repeated calls.
    ///
    /// Status: a **new** agent is [`AgentStatus::Approved`] (the AS consent was the approval) unless
    /// the new-agent gate is on ([`Self::require_agent_approval`]), in which case it lands
    /// [`AgentStatus::Pending`] until approved. An **existing** agent keeps its stored status, so a
    /// repeated JWT call never bumps a Pending agent to Approved (the bug that made the approval gate
    /// un-enforceable), and an operator's Pending decision sticks until they explicitly approve.
    ///
    /// Revocation: a revoked stored row refuses every token for this client, refreshed ones included,
    /// while its agent exists. A revoked row whose agent was removed brings the client back Pending.
    fn session_from_jwt(
        &self,
        claims: crate::oauth::VerifiedClaims,
    ) -> Result<Session, GatewayError> {
        // The consent page tells the user an identity-only sign-in "gets no access to your gateway, and no ability to act as an agent"; a token minted off that consent carries no `mcp` scope, and the AS cannot be the only thing holding the line.
        if !claims.is_agent() {
            return Err(GatewayError::Denied(format!(
                "this token cannot act as an agent: it lacks the `{}` scope (its scope is {}); the client must ask for `{}` when it signs in at permaura.com",
                crate::oauth::MCP_SCOPE,
                claims.scope.as_deref().map_or("absent".to_string(), |s| format!("\"{s}\"")),
                crate::oauth::MCP_SCOPE,
            )));
        }
        // Before anything is registered, so a paused worker learns of no new client.
        self.refuse_if_agents_paused()?;
        let agent_id = oauth_agent_id(&claims);
        let now = now_ms();
        let prior = self.store.get_agent(&agent_id)?;
        let stored = self.store.get_session(&oauth_session_id(&agent_id))?;
        let tombstone = stored.as_ref().is_some_and(|s| s.revoked);
        if tombstone && prior.is_some() {
            return Err(GatewayError::Unauthorized("session has been revoked".into()));
        }
        let name = claims
            .name
            .clone()
            .or_else(|| prior.as_ref().map(|a| a.name.clone()))
            .unwrap_or_else(|| agent_id.clone());
        // The admission a held call is bound to (see `hold_lapse`), so it is set only when the agent is admitted, never on a rename.
        let enrolled_at = prior.as_ref().map(|a| a.enrolled_at).unwrap_or(now);
        let status = match prior.as_ref() {
            Some(a) => a.status, // preserve: never auto-approve an agent an operator left Pending
            // Removed by its owner and calling again. Consent at the AS was given before the removal
            // and says nothing about it, so only a fresh decision here brings it back.
            None if tombstone || self.require_agent_approval() => AgentStatus::Pending,
            None => AgentStatus::Approved,
        };
        let needs_write = match prior.as_ref() {
            None => true,
            Some(a) => a.name != name || a.status != status,
        };
        // The direct-agent path, and the reason this check cannot live in the console: an OAuth
        // client that reaches a hosted worker's `/mcp` with a valid token registers itself here,
        // never touching permaura.com. Only a brand-new agent is charged. Renaming one, or
        // reconnecting an existing one, must keep working at the ceiling.
        if prior.is_none() {
            self.refuse_if_over_allowance(crate::allowances::Allowance::Agents, None)?;
        }
        if needs_write {
            self.store.put_agent(Agent {
                id: agent_id.clone(),
                name: name.clone(),
                status,
                enrolled_at,
            })?;
        }
        // Only a BRAND-NEW agent the approval gate left Pending. A repeat call from an agent already
        // waiting rewrites nothing and must not ring again, and consent alone lands Approved, which
        // needs no decision from anybody.
        if prior.is_none() && status == AgentStatus::Pending {
            self.announce_agent_pending(&agent_id, &name);
        }
        let session = Session {
            class: Default::default(),
            opened_by: None,
            id: oauth_session_id(&agent_id),
            agent_id: agent_id.clone(),
            user_id: None,
            device_id: None,
            // A RANDOM, unguessable token. `agent_id` is `oauth:<azp>`, and `azp` is the OAuth client
            // id, a PUBLIC identifier, readable in any JWT payload. A deterministic `tok_oauth:<azp>`
            // was therefore trivially forgeable: `authenticate()` checks `session_by_token` before the
            // JWT path, so once any agent had connected, presenting `Bearer tok_oauth:<azp>` returned
            // its session with no valid JWT at all. The JWT is the real credential (verified on every
            // request); this token exists only to satisfy the session schema and must never be
            // presentable. The session id stays deterministic so a held approval still correlates.
            token: format!("tok_{}", short_id()),
            role: SessionRole::Agent,
            created_at: now,
            revoked: false,
            expires_at: Some(now + crate::store::AGENT_SESSION_TTL_MS),
            last_used_at: None,
            actor: None,
        };
        let opened = if tombstone {
            self.store.put_session(session.clone())?;
            true
        } else if stored.is_none() {
            if !self.store.insert_session(session.clone())? {
                // A row landed after the read above. A concurrent first call's is as good as ours; an
                // owner's tombstone from removing the agent meanwhile is a decision this call must not undo.
                if let Some(row) = self.store.get_session(&session.id)? {
                    if row.revoked {
                        return Err(GatewayError::Unauthorized("session has been revoked".into()));
                    }
                    return Ok(row);
                }
            }
            true
        } else {
            false
        };
        if opened {
            let summary = serde_json::json!({
                "via": "oauth",
                "consented_by": crate::audit_bound::cut_text(&claims.sub),
                "agent_status": status,
                "new_agent": prior.is_none(),
                "after_removal": tombstone,
            });
            // A session whose issue is not in the chain does not stand; the next call tries again.
            if let Err(e) = self.audit_authority(SESSION_OPEN_ACTION, &session.id, &session, summary) {
                match stored.filter(|_| tombstone) {
                    Some(previous) => {
                        let _ = self.store.put_session(previous);
                    }
                    None => {
                        let _ = self.store.delete_session(&session.id);
                    }
                }
                return Err(e);
            }
        }
        Ok(session)
    }

    /// Redeem `code` as a one-time enrolment code and mint a Pending, Agent-role session for a
    /// freshly-created agent (token = the code). Returns `None` if `code` is not a live
    /// enrolment code. Handles the concurrent-first-call race by returning any session that a
    /// racing call already bootstrapped under the same token.
    fn bootstrap_from_enrolment_code(&self, code: &str) -> Result<Option<Session>, GatewayError> {
        let now = now_ms();
        // Every bearer that names nothing ends here, and consuming is a write: on a hosted worker one that waits on the snapshot upload. Looked up first, so a stranger's junk costs a read.
        if !self.store.enrolment_code_redeemable(code, now)? {
            return self.store.session_by_token(code);
        }
        let ticket = match self.store.consume_enrolment_code(code, now)? {
            Some(t) => t,
            // Already used (or never valid), but a concurrent first call may have just
            // bootstrapped the session under this same token; surface it if so.
            None => return self.store.session_by_token(code),
        };

        // A unique agent id that can never collide with an operator/seeded agent.
        let slug: String = ticket
            .label
            .as_deref()
            .unwrap_or("agent")
            .to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        let slug = slug.trim_matches('-');
        let agent_id = format!(
            "{}-{}",
            if slug.is_empty() { "agent" } else { slug },
            &short_id()[..8]
        );
        let name = ticket.label.clone().unwrap_or_else(|| "Enrolled agent".to_string());
        // The code has already been consumed by this point, so a refusal here spends it. That is the
        // right way round: the alternative is checking before the consume and leaving a live code
        // behind on every refusal, which is a code an operator believes they issued once.
        self.refuse_if_over_allowance(crate::allowances::Allowance::Agents, None)?;
        self.store.put_agent(Agent {
            id: agent_id.clone(),
            name: name.clone(),
            status: AgentStatus::Pending,
            enrolled_at: now,
        })?;
        self.announce_agent_pending(&agent_id, &name);

        let session = Session {
            class: Default::default(),
            opened_by: None,
            id: format!("sess_{}", short_id()),
            agent_id,
            user_id: None,
            device_id: None,
            // The token IS the code, so the client's static bearer keeps resolving to this
            // session on every subsequent call.
            token: code.to_string(),
            role: SessionRole::Agent,
            created_at: now,
            revoked: false,
            expires_at: Some(now + crate::store::AGENT_SESSION_TTL_MS),
            last_used_at: None,
            actor: None,
        };
        self.grant_enrolled_session(&session, &ticket, "bearer")?;
        Ok(Some(session))
    }

    /// Grant the session an enrolment code was just redeemed into: `permaura.agent.enroll` is recorded
    /// first and the session put after it, as one unit, so a bearer whose issue is not in the chain is
    /// never granted. A record that lands and a put that fails leaves a record of an enrolment that did
    /// not stand, the safe way round. The code is spent either way. `via` names the redemption path, and
    /// the code's own times join the record to its mint without naming the code.
    pub fn grant_enrolled_session(&self, session: &Session, ticket: &crate::store::EnrolmentCode, via: &str) -> Result<(), GatewayError> {
        let summary = serde_json::json!({
            "session_id": &session.id,
            "label": ticket.label,
            "status": "pending",
            "via": via,
            "code_created_at": ticket.created_at,
            "code_expires_at": ticket.expires_at,
        });
        self.store.change_with_record(&mut || {
            self.audit_authority(AGENT_ENROLL_ACTION, &session.agent_id, session, summary.clone())?;
            self.store.put_session(session.clone())
        })
    }


    /// Ring for an agent that has just enrolled and is sitting Pending.
    ///
    /// THE GATE THAT RANG NOBODY. Every other holding rung tells somebody: a held call announces and
    /// pushes, a held mutation pushes to the enrolled device. A new agent, which is the gate every
    /// connection passes through exactly once, only ever appeared as a row on a page the operator had
    /// to already be looking at. On a hosted worker nobody is looking at a terminal, so the agent the
    /// operator had just invited sat there silently and the setup read as broken.
    ///
    /// Both rungs, like the approval sites: an announcing gateway holds no push tokens of its own
    /// ([`crate::push::PushRegistry::holds_push_tokens`]) and the control plane sends for it, while a
    /// gateway that announces nothing is the sender itself. Each call is a no-op in the other's case.
    ///
    /// Spawned through the current handle rather than `tokio::spawn`, because the enrolment paths are
    /// synchronous and are exercised by tests with no runtime under them. No runtime means no
    /// notification, which is the same cost as a dropped one and never a failed enrolment.
    pub fn announce_agent_pending(&self, agent_id: &str, agent_name: &str) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let announce_to = self.announcer.links();
        handle.spawn(crate::announce::announce_agent_pending(announce_to, crate::announce::AnnouncedAgent {
            agent_id: agent_id.to_string(),
            agent_name: agent_name.to_string(),
        }));
        let tokens = self.push.tokens();
        if !tokens.is_empty() {
            handle.spawn(crate::push::send_expo_push(
                tokens,
                crate::push::PushKind::AgentPending,
                agent_id.to_string(),
            ));
        }
    }

    /// Clear an agent's notice once it has been approved or removed. Best-effort: a lost resolve
    /// leaves a row standing until somebody opens the queue and reconciles it.
    pub fn announce_agent_resolved(&self, agent_id: &str) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let announce_to = self.announcer.links();
        handle.spawn(crate::announce::announce_resolved(announce_to, agent_id.to_string()));
    }

    /// The full enforcement loop for a single capability invocation.
    ///
    /// `session` is the already-authenticated caller; `capability_id` and `params`
    /// come from the agent; `reason` is the agent's stated intent (audited, never
    /// trusted for authorization).
    pub async fn invoke(
        &self,
        session: &Session,
        capability_id: &str,
        params: &serde_json::Value,
        reason: Option<&str>,
        execution_location: ExecutionLocation,
    ) -> Result<InvokeOutcome, GatewayError> {
        let params = crate::memory::AgentParams::uncharged(params.clone());
        self.invoke_admitted(session, capability_id, params, reason, execution_location).await
    }

    /// The params of an agent call about to be held, as the text its row keeps: a held call waits for a human with its params in the store, and every approvals listing reads every pending row. Their tree was checked against the one ceiling before the policy held the call ([`crate::memory::MemoryBudget::admit_unpacked`]); text this gateway writes longer than it was sent is kept at its stored length and charged when the call is approved ([`crate::memory::MemoryBudget::parse_held`]), never refused for being longer. The row they make is checked against the queue's total by [`Self::refuse_over_hold_bytes`].
    fn admit_hold(&self, params: &serde_json::Value) -> JsonText {
        JsonText::from_value(params)
    }

    /// Refuse an agent hold whose row, counted whole as the pending ones are, would take them past the held-params ceiling.
    /// A hold alone in the queue is admitted whatever its row takes, so a call [`Self::admit_hold`] passed is never refused where no retry could clear it ([`crate::memory::held_total_bytes`]).
    fn refuse_over_hold_bytes(&self, approval: &PendingApproval) -> Result<(), GatewayError> {
        let pending = self.store.pending_hold_bytes()?;
        let ceiling = self.memory.held_total_bytes();
        if pending > 0 && pending.saturating_add(crate::store::row_len(approval)) > ceiling {
            return Err(GatewayError::TooManyRequests {
                reason: "held_params".to_string(),
                message: format!(
                    "the calls already waiting for a human on this gateway hold {pending} bytes, and this one \
                     would take them past the {ceiling}-byte ceiling; no new call can be held until some are resolved"
                ),
                retry_after_secs: HELD_PARAMS_RETRY_AFTER_SECS,
                scope: None,
            });
        }
        Ok(())
    }

    /// [`Self::invoke`] with params a route has already parsed under the worker's JSON memory budget. The execution task holds a clone of `params`, never a copy of the tree, so the room they take is given back when the execution is done with them, not when the caller hangs up.
    pub async fn invoke_admitted(
        &self,
        session: &Session,
        capability_id: &str,
        mut params: crate::memory::AgentParams,
        reason: Option<&str>,
        execution_location: ExecutionLocation,
    ) -> Result<InvokeOutcome, GatewayError> {
        // The reason lands on the hold and in every audit event, which every member reads, and an agent
        // can send megabytes of it; it is kept cut and masked from here on.
        let stored_reason = reason.map(crate::approval_display::stored_intent);
        let reason = stored_reason.as_deref();
        // Remoteness is this gateway's own knowledge. A caller's `local_only` is the default and sits
        // outside `request_hash`, so it may make a call stricter but never move a hosted call local.
        let execution_location = if self.hosted { ExecutionLocation::RemoteAllowed } else { execution_location };
        // ── 0a. The execution hold, above everything including the capability lookup. ────────
        // The contract places this before the pre-execution `"attempt"` append, which is the fence
        // every execution passes; it is here instead, at the very top, because every gate below can
        // append an audit event and on a hosted worker an audit append is a full snapshot upload. A
        // refusal that wrote to the store would make refusing a request more expensive than serving
        // one, and would grow the audit chain of a tenant that is being held precisely so its state
        // stops moving. Nothing here reads or writes the store.
        self.refuse_if_held()?;
        self.refuse_if_agents_paused()?;
        // A stopping gateway admits nothing new, and says so before any store work. The permit goes
        // with the execution task below, so the drain waits for the terminal event, not the response.
        let permit = self.executions.admit(None)?;
        // A session whose calls keep being denied is refused here, unrecorded, before its denials can fill the chain.
        self.audit_ceiling.admit_session(&session.id)?;

        // ── 0b. Restored authority nobody has confirmed. ─────────────────────────────────────
        // Read once, checked at each gate below against the same answer, and beside the hold rather
        // than inside it: the hold is lifted the moment the list is closed, and these refusals have
        // to keep binding until each item is decided. A denial rather than a refusal, because every
        // other "this principal may not act" gate in this method is a denial and an operator reading
        // the chain should find this one in the same shape as the rest.
        let review = self.reconciliation()?;

        // ── 1. Resolve the capability from the catalog. ─────────────────────────
        let cap = self
            .store
            .get_capability(capability_id)?
            .ok_or_else(|| GatewayError::NotFound(format!("capability '{capability_id}'")))?;
        crate::approval_display::refuse_unpinned_params(&cap, params.value())?;
        // An agent's URL is held, shown and signed in the form the client sends it.
        let mut url_growth = 0;
        if let Some(connection) = self.store.get_connection(&cap.resource)? {
            if connectors::takes_agent_url(&connection.connector, &cap) {
                let sent = params.get("url").and_then(|v| v.as_str()).map_or(0, str::len) as u64;
                if connectors::canonicalize_agent_params(&connection.connector, &cap, params.make_mut()) {
                    let held = params.get("url").and_then(|v| v.as_str()).map_or(0, str::len) as u64;
                    url_growth = connectors::json_budget::chunk_bytes(held).saturating_sub(connectors::json_budget::chunk_bytes(sent));
                }
            }
        }
        // The one ceiling on an agent call's unpacked size, before the policy decides whether to hold the call, so a held and an unheld call are admitted alike. The estimate is recorded as `unpacked_bytes` on the event every call that reaches the policy writes first (a denial, a hold or the attempt), so the ceiling can be checked against real traffic. A route that read the body checked the estimate it made of it before parsing; the URL the gateway canonicalized is counted at its new length.
        let unpacked = match params.unpacked_bytes() {
            Some(sent) => sent.saturating_add(url_growth),
            None => connectors::json_budget::estimate(JsonText::from_value(params.value()).get().as_bytes()),
        };
        self.memory.admit_unpacked(unpacked, "service")?;
        let shared_params = params;
        let params: &serde_json::Value = &shared_params;

        let (connection, resolution, reservation) =
            match self.gate(session, &cap, params, execution_location, review.as_ref(), true)? {
                Gate::Refused { decision, detail } => {
                    let mut summary = serde_json::json!({ "reason": decision.reason, "intent": reason, "unpacked_bytes": unpacked });
                    if let (Some(summary), serde_json::Value::Object(detail)) = (summary.as_object_mut(), detail) {
                        summary.extend(detail);
                    }
                    self.audit(session, &cap, "deny", execution_location, summary)?;
                    return Ok(InvokeOutcome::Denied { decision });
                }
                Gate::Resolved { connection, resolution, reservation } => (connection, resolution, reservation),
            };
        let connection_id = cap.resource.clone();
        let decision = resolution.decision;
        let rung = resolution.rung;
        let grant_id = resolution.matched_grant_id;
        let policy_id = resolution.matched_policy_id;
        let resolution_quorum = resolution.quorum.max(1);
        let policy_redactions = resolution.redact_fields;

        // ── 6. Branch on the verdict. ───────────────────────────────────────────
        match decision.kind {
            DecisionKind::Deny => {
                self.audit(session, &cap, "deny", execution_location, serde_json::json!({
                    "reason": decision.reason, "intent": reason,
                    "grant_id": grant_id, "policy_id": policy_id,
                    "unpacked_bytes": unpacked,
                }))?;
                Ok(InvokeOutcome::Denied { decision })
            }
            DecisionKind::RequiresApproval => {
                let message = decision
                    .approval
                    .as_ref()
                    .map(|a| a.message.clone())
                    .unwrap_or_else(|| format!("Approve '{}'?", cap.id));
                // The rung is either `approve` or `device_signed` here (the two holding rungs);
                // it selects whether a bare operator bearer may later resolve this approval.
                let required_tier = rung.tier_str().unwrap_or("approve").to_string();
                let admitting = self.memory.admit_one_hold().await;
                let held_params = self.admit_hold(params);
                let created_at = now_ms();
                let approval = PendingApproval {
                    id: format!("appr_{}", short_id()),
                    session_id: session.id.clone(),
                    capability: cap.id.clone(),
                    resource: connection_id.clone(),
                    message,
                    status: "pending".into(),
                    grant_id: grant_id.clone(),
                    policy_id: policy_id.clone(),
                    params: held_params,
                    result: None,
                    result_status: None,
                    resolution_reason: None,
                    created_at,
                    expires_at: crate::relay::hold_expiry(created_at),
                    // The catalogue's classification as it stood when the call was held. Reading it
                    // back out of the catalogue at render time would let an edit to this capability
                    // rewrite what the human is being asked about a request held before the edit.
                    risk: Some(cap.risk),
                    action_description: Some(held_call_sentence(&cap)),
                    intent: reason.map(str::to_string),
                    required_tier: required_tier.clone(),
                    // Only the device_signed rung can count signatures; the engine already
                    // returns 1 for every other rung, but be explicit about the coupling.
                    required_signatures: if rung == Rung::DeviceSigned {
                        resolution_quorum
                    } else {
                        1
                    },
                    signatures: Vec::new(),
                    requested_by: None,
                };
                self.refuse_over_hold_bytes(&approval)?;
                self.store.insert_approval(approval.clone())?;
                drop(admitting);
                // Tell the control plane, so a phone pointed at ANY of this operator's workspaces
                // can see it. Detached and best-effort: the hold is real because it is in this
                // store, and a lost announcement costs a notification, never an enforcement.
                //
                // The agent is resolved to its human name here rather than sent as a session id,
                // because this is the only place that can: the control plane has no view of this
                // gateway's sessions. A lookup that fails sends nothing rather than a raw id.
                //
                // The grade and the deadline come off the row, never from the capability catalogue:
                // risk is editable, so classifying at announce time would let an edit rewrite what a
                // queue says about a request held an hour ago.
                let announce_to = self.announcer.links();
                tokio::spawn(crate::announce::announce_hold(announce_to, crate::announce::AnnouncedHold {
                    approval_id: approval.id.clone(),
                    capability: cap.id.clone(),
                    resource: connection_id.clone(),
                    risk: approval.risk_label(),
                    required_tier: required_tier.clone(),
                    agent: self
                        .store
                        .get_agent(&session.agent_id)
                        .ok()
                        .flatten()
                        .map(|a| a.name),
                    expires_at: approval.expires_at,
                    requested_by: None,
                }));
                // Best-effort: push the approval to the registered phone(s) so the human
                // can approve from the lock screen. Detached: never delays the response.
                let tokens = self.push.tokens();
                if !tokens.is_empty() {
                    tokio::spawn(crate::push::send_expo_push(
                        tokens,
                        crate::push::PushKind::ApprovalRequested,
                        approval.id.clone(),
                    ));
                }
                // Same event to Slack when a webhook is configured. `device_signed`-tier approvals
                // are dropped inside the notifier, not here; see [`crate::notify`] invariant 1.
                // `AnnouncedApproval` is the projection without `params`, so the agent's request
                // body never reaches the notification task.
                tokio::spawn(crate::notify::notify_approval((&approval).into()));
                self.audit(
                    session,
                    &cap,
                    "requires_approval",
                    execution_location,
                    serde_json::json!({
                        "approval_id": approval.id,
                        "reason": decision.reason,
                        "intent": reason,
                        "grant_id": grant_id,
                        "policy_id": policy_id,
                        "required_tier": required_tier,
                        "unpacked_bytes": unpacked,
                    }),
                )?;
                Ok(InvokeOutcome::RequiresApproval { decision, approval })
            }
            DecisionKind::Allow => {
                // The hot audit store's ceiling, at the fence and before the append it fences with.
                // Nothing below this point can decline to record, so the last moment at which a new
                // execution can be refused for lack of room to record it is here. A refusal appends
                // nothing and mutates nothing, which on a hosted worker is the whole point: a
                // refusal that wrote would cost a full snapshot upload. The hold above already
                // refused a held tenant, and that order is deliberate: telling a held tenant to
                // slow down would be the wrong instruction.
                self.refuse_if_audit_full()?;
                // Resolved before the fence so a store that cannot answer refuses the call rather than
                // letting a result out under a narrower set than the one it was meant to get.
                let redact_keys = self.redaction_for(&connection, &cap, &policy_redactions)?;
                // Durable intent before the credential is used. The upload this append forces is the
                // fence: an instance whose store another instance has moved on meets the 412 here and
                // exits before anything external happens, and a store that cannot reach its storage
                // refuses here. Nothing can recall an upstream request already in flight, so the
                // record has to come first.
                let execution_id = format!("exe_{}", short_id());
                let attempt = audit_payload(
                    session,
                    &cap,
                    "attempt",
                    execution_location,
                    serde_json::json!({
                        "intent": reason,
                        "grant_id": &grant_id,
                        "policy_id": &policy_id,
                        "execution_id": &execution_id,
                        "unpacked_bytes": unpacked,
                    }),
                );
                if let (_, Some(not_durable)) = self.store.append_audit_fence(attempt)? {
                    // The attempt is recorded here but its upload failed, so nothing may run on it.
                    // It is closed as refused now, and the next upload carries the pair.
                    let mut refused = TerminalEvent {
                        store: self.store.clone(),
                        session: session.clone(),
                        cap: cap.clone(),
                        execution_location,
                        intent: reason.map(str::to_string),
                        grant_id: grant_id.clone(),
                        policy_id: policy_id.clone(),
                        approval: None,
                        execution_id: Some(execution_id.clone()),
                        trace: Arc::new(ExecutionTrace::new()),
                        armed: true,
                    };
                    if let Err(store_err) = refused.record_refused_at_fence(&not_durable) {
                        tracing::error!(
                            capability = %cap.id,
                            error = %store_err,
                            "the terminal audit event for an execution refused at its fence is not durable"
                        );
                    }
                    return Err(not_durable);
                }
                let notified = rung == Rung::Notify;
                // Past the fence, the execution and the one terminal event that must follow it run
                // in a task of their own, and this future only waits on its handle. Dropping this
                // future (the inbound request timeout firing, an agent hanging up) therefore
                // cancels nothing: the task runs to its own ceiling and records what happened.
                //
                // The alternative, letting the drop propagate and writing an "unknown" from a guard
                // here, would abandon a request that had already been sent and leave the chain
                // permanently unable to say whether it landed. Nothing can recall the request
                // either way, so finishing it is the only version that learns the answer. Two costs,
                // both accepted: the execution outlives the admission-control permit, which is
                // released with the request, and it outlives the caller, which has stopped
                // listening. `limits::execution_budget()` is what bounds it.
                let trace = Arc::new(ExecutionTrace::new());
                let executed = {
                    let service = self.clone();
                    let mut terminal = TerminalEvent {
                        store: self.store.clone(),
                        session: session.clone(),
                        cap: cap.clone(),
                        execution_location,
                        intent: reason.map(str::to_string),
                        grant_id: grant_id.clone(),
                        policy_id: policy_id.clone(),
                        approval: None,
                        execution_id: Some(execution_id),
                        trace: trace.clone(),
                        armed: true,
                    };
                    let cap = cap.clone();
                    let params = shared_params.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        // Released once the terminal append has charged the grant, never before it.
                        let _reservation = reservation;
                        match service.execute_allowed(&cap, &params, &redact_keys, &trace).await {
                            Ok(executed) => {
                                terminal.record_allow(&executed, notified)?;
                                Ok((executed.status, executed.redacted, executed.room))
                            }
                            Err(e) => {
                                // The caller is told what happened to THEIR call, so the execution
                                // error wins over a failure to record it. A store that cannot make
                                // the event durable is already loud: it is quarantined, `degraded()`
                                // says so, and the line below carries the store's own account of
                                // whether the event is held locally awaiting an upload.
                                if let Err(store_err) = terminal.record_error(&e) {
                                    tracing::error!(
                                        capability = %cap.id,
                                        error = %store_err,
                                        "the terminal audit event for a failed execution is not durable"
                                    );
                                }
                                Err(e)
                            }
                        }
                    })
                };
                let (status, redacted, room) = match executed.await {
                    Ok(result) => result?,
                    // The task is never aborted, so this is a panic inside the connector path (the
                    // guard has already written the terminal event on the way out) or a runtime
                    // shutting down underneath it.
                    Err(join) => {
                        return Err(GatewayError::Internal(format!(
                            "the execution task for '{}' did not finish: {join}",
                            cap.id
                        )))
                    }
                };
                // The `notify` rung executes immediately but pushes an after-the-fact alert so the
                // operator stays aware of what ran unattended. Detached: never delays the response.
                if notified {
                    let tokens = self.push.tokens();
                    if !tokens.is_empty() {
                        tokio::spawn(crate::push::send_expo_push(
                            tokens,
                            crate::push::PushKind::Executed,
                            String::new(),
                        ));
                    }
                    tokio::spawn(crate::notify::notify_executed(
                        cap.id.clone(),
                        connection_id.clone(),
                    ));
                }
                Ok(InvokeOutcome::Allowed {
                    decision,
                    result: redacted,
                    status,
                    room,
                })
            }
        }
    }

    /// The verdict [`Self::invoke`] would reach for this call right now, through the same gates, without
    /// running it: nothing executes, nothing is held, reserved or written to the audit chain. Backs
    /// `permaura_explain_denial` and `POST /v1/invoke` with `explain_only`.
    pub fn explain(
        &self,
        session: &Session,
        capability_id: &str,
        params: &serde_json::Value,
        execution_location: ExecutionLocation,
    ) -> Result<Decision, GatewayError> {
        let execution_location = if self.hosted { ExecutionLocation::RemoteAllowed } else { execution_location };
        let review = self.reconciliation()?;
        let cap = self
            .store
            .get_capability(capability_id)?
            .ok_or_else(|| GatewayError::NotFound(format!("capability '{capability_id}'")))?;
        crate::approval_display::refuse_unpinned_params(&cap, params)?;
        Ok(match self.gate(session, &cap, params, execution_location, review.as_ref(), false)? {
            Gate::Refused { decision, .. } => decision,
            Gate::Resolved { resolution, .. } => resolution.decision,
        })
    }

    /// Every gate [`Self::invoke`] puts a call through before it acts on the verdict: the pause, the
    /// connection, egress, the agent, custody, restored authority and the engine with each grant's
    /// budget. Reads only; `reserve` takes the budget reservation an allowed call that will run holds.
    fn gate(
        &self,
        session: &Session,
        cap: &Capability,
        params: &serde_json::Value,
        execution_location: ExecutionLocation,
        review: Option<&crate::reconcile::ReconciliationRecord>,
        reserve: bool,
    ) -> Result<Gate, GatewayError> {
        let unreviewed = |kind, id: &str| Self::refuse_if_unreviewed(review, kind, id);
        use crate::reconcile::ReviewKind;

        // ── 0. Global pause (operator kill switch): deny EVERY action while paused, above all
        // policy. The gateway stays up so the operator can unpause; only invokes are blocked. ──
        if self.is_paused() {
            let decision = Decision::deny("All agents are paused by the operator.".to_string());
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "paused": true }) });
        }

        // The capability's `resource` is the connection id it acts on. Grants and policies
        // key on the *action id*: the capability id minus its connector prefix
        // (e.g. `braintree.transactions.search` → `transactions.search`).
        let connection_id = cap.resource.clone();
        let policy_action = cap
            .id
            .split_once('.')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| cap.id.clone());

        // ── 2. Connection gate: the connection must EXIST and the capability
        // must not be switched off. Both halves are deny preconditions: a capability whose
        // connection was removed (or never created) is denied outright, and a disabled
        // capability is denied for every grant, above any policy (the real capability toggle). ──
        let connection = match self.store.get_connection(&connection_id)? {
            Some(c) => c,
            None => {
                let decision = Decision::deny(format!(
                    "No connection '{connection_id}' is configured. Denied."
                ));
                return Ok(Gate::Refused { decision, detail: serde_json::json!({ "connection_missing": true }) });
            }
        };
        if let Some(deny_reason) = unreviewed(ReviewKind::Connection, &connection_id) {
            let decision = Decision::deny(deny_reason);
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "needs_review": "connection" }) });
        }
        if connection.disabled {
            let decision = Decision::deny(format!(
                "Connection '{}' is disabled: every capability on it is paused.",
                connection.name
            ));
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "connection_disabled": true }) });
        }
        if connection.disabled_capabilities.iter().any(|c| c == &cap.id) {
            let decision = Decision::deny(format!(
                "Capability '{}' is switched off on connection '{}'.",
                cap.id, connection.name
            ));
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "capability_disabled": true }) });
        }
        if let Some(why) = self.connection_revocation(&connection)? {
            let decision = Decision::deny(format!(
                "Connector '{}' is revoked ({why}), and connection '{}' holds its capabilities: every one of them is refused until the revocation list stops naming it. Make the connection again from a version that is not revoked.",
                connection.connector, connection.name
            ));
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "connector_revoked": true }) });
        }

        // ── 2b. Egress allowlist gate (generic-HTTP). The proxy's target host is agent-supplied,
        // so it must be on the operator's connection allowlist; an empty allowlist fails closed.
        // This is the SSRF guard at the policy layer; the connector HTTP client re-screens every
        // address (blocking metadata/private ranges) as the backstop, but this denies up front and
        // is audited. ─────────────────────────────────────────────────────────────────────────
        if let Some(block_reason) = egress_refusal(&connection, &cap, params) {
            let decision = Decision::deny(block_reason);
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "egress_blocked": true }) });
        }

        // ── 3. Agent gate: only an approved agent may have its calls authorized. A
        // self-enrolled agent sits Pending until a human approves it. ────────────────────
        let agent_approved = self
            .store
            .get_agent(&session.agent_id)?
            .map(|a| a.is_approved())
            .unwrap_or(false);
        if !agent_approved {
            let decision = Decision::deny(format!(
                "Agent '{}' is not approved. An operator must approve it before it can act.",
                session.agent_id
            ));
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "agent_pending": true }) });
        }

        if let Some(deny_reason) = unreviewed(ReviewKind::Agent, &session.agent_id) {
            let decision = Decision::deny(deny_reason);
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "needs_review": "agent" }) });
        }

        // ── 4. Custody gate: a local-only secret may never execute remotely. ──────────────
        // Local-only is a secret that names where it may run and does not name remote. One that names
        // nothing, which is every credential added through the console, records no restriction.
        if execution_location == ExecutionLocation::RemoteAllowed {
            if let Some(sec) = self.store.get_secret(&cap.secret_id)? {
                let allowed = &sec.metadata.allowed_execution_locations;
                if !allowed.is_empty() && !allowed.contains(&ExecutionLocation::RemoteAllowed) {
                    let decision = Decision::deny(format!(
                        "The credential for '{connection_id}' is local-only but the request would execute remotely."
                    ));
                    return Ok(Gate::Refused { decision, detail: serde_json::json!({}) });
                }
            }
        }

        if let Some(deny_reason) = unreviewed(ReviewKind::Secret, &cap.secret_id) {
            let decision = Decision::deny(deny_reason);
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "needs_review": "secret" }) });
        }

        // ── 4b. Request-shape gate, last before policy because policy judges the capability's
        // action: the input has to keep the request inside that action. A read capability may not
        // carry a GraphQL mutation, and a path identifier may not carry URL syntax that reaches another
        // endpoint or query. ─────────────────────────────────────────────────────────────────────
        if let Some(refusal) = connectors::request_refusal(&connection.connector, cap, params) {
            let decision = Decision::deny(refusal.reason);
            return Ok(Gate::Refused { decision, detail: serde_json::json!({ "request_refused": refusal.code }) });
        }

        // ── 5. Policy resolution: the grants targeting this agent (or all agents) whose
        // policy is scoped to this connection, with each grant's call budget applied. ─────
        let amount = params.get("amount").and_then(|v| v.as_f64());
        let input = DecisionInput {
            capability_id: policy_action,
            action: cap.action,
            connection_id: connection_id.clone(),
            risk: cap.risk,
            capability_requires_approval: cap.requires_approval,
            agent_id: session.agent_id.clone(),
            context: RequestContext {
                session_id: session.id.clone(),
                requested_at: OffsetDateTime::now_utc(),
                execution_location,
                amount,
            },
        };

        let grants = self.store.list_grants()?;
        let policies = self.store.policies_for_connection(&connection_id)?;
        let now = now_ms();
        let engine = PolicyEngine::with(grants.clone(), policies);
        let (resolution, reservation) = {
            let mut book = crate::store::bridge::lock_donating(&self.budget_book).unwrap_or_else(|e| e.into_inner());
            let usage = AuditUsage::measure(self.store.as_ref(), &grants, now)?.with_reserved(&book);
            let resolution = engine.resolve(&input, &usage);
            let reservation = match (&resolution.decision.kind, &resolution.matched_grant_id) {
                (DecisionKind::Allow, Some(grant)) if reserve => {
                    Some(book.reserve(&self.budget_book, grant, &session.agent_id))
                }
                _ => None,
            };
            (resolution, reservation)
        };
        // The grant the engine chose, last of the five because it is the only one the engine names.
        if let Some(deny_reason) =
            resolution.matched_grant_id.as_deref().and_then(|g| unreviewed(ReviewKind::Grant, g))
        {
            return Ok(Gate::Refused {
                decision: Decision::deny(deny_reason),
                detail: serde_json::json!({
                    "needs_review": "grant",
                    "grant_id": resolution.matched_grant_id,
                    "policy_id": resolution.matched_policy_id,
                }),
            });
        }
        Ok(Gate::Resolved { connection, resolution, reservation })
    }

    /// Persist a now-terminal approval and tell the control plane it has stopped waiting.
    ///
    /// One helper rather than the announcement repeated at each of the four exits of
    /// [`Self::resolve_approval`], because a fifth exit added later would otherwise silently leave a
    /// row standing on somebody's dashboard for a decision that had already been made.
    ///
    /// The announcement is detached and carries no outcome. See [`crate::announce`]. The store write
    /// is what makes the resolution real; this only tells the control plane to stop showing it.
    ///
    /// The row is moved into the write, never copied beside it: a resolved row carries its call's result, and a copy kept here held it again beside the row's text.
    fn settle_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
        let id = approval.id.clone();
        self.store.put_approval(approval)?;
        let announce_to = self.announcer.links();
        tokio::spawn(crate::announce::announce_resolved(announce_to, id));
        Ok(())
    }

    /// [`Self::settle_approval`], answering with the row as the store now keeps it: the approver is told what the agent will read, a result over [`crate::store::MAX_STORED_RESULT_BYTES`] included, which is its size marker.
    /// The read back can fail after the row is written; the decision stands then, so the error says it was recorded, and approving again answers with the row.
    fn settle_and_answer(&self, approval: PendingApproval) -> Result<PendingApproval, GatewayError> {
        let (id, status) = (approval.id.clone(), approval.status.clone());
        self.settle_approval(approval)?;
        let unread = |why: String| {
            tracing::error!(approval_id = %id, %status, error = %why, "a settled approval could not be read back to answer its approver");
            GatewayError::Internal(format!(
                "approval '{id}' was recorded as {status}, but could not be read back to answer this request ({why}); it is no longer pending, so read it, or approve it again to be answered with it, rather than asking for the call again"
            ))
        };
        match self.store.get_approval(&id) {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(unread("it is not in the store".to_string())),
            Err(e) => Err(unread(e.to_string())),
        }
    }

    /// Record that a resolution failed after its claim was spent, on the two control-plane branches
    /// of [`Self::resolve_approval`] that have no upstream call to await.
    ///
    /// One terminal event and one row change, and the caller's original error is what comes back:
    /// the human who pressed approve is told what went wrong with their action, and the chain is
    /// told that the action is over. Both writes are best effort and both are loud, because the
    /// usual reason either of them fails is that the store is already quarantined, which is the same
    /// reason the resolution failed.
    ///
    /// `refused` rather than `unknown` on these two branches, and that is not a shortcut: neither
    /// reaches a transport. A held mutation is a local store write and a held vault export applies
    /// nothing at all, so "the effect did not happen" is a claim this gateway can actually make.
    fn unresolve(
        &self,
        approval: &mut PendingApproval,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
        error: GatewayError,
    ) -> GatewayError {
        let mut payload = AuditPayload::new(
            approval.capability.clone(),
            approval.resource.clone(),
            "error",
        );
        payload.summary = serde_json::json!({
            "approval_id": approval.id,
            "method": method,
            "approver": approver,
            "outcome": ExecutionOutcome::Refused.as_str(),
            "error_kind": error_kind(&error),
        });
        self.approver_detail(approval, method, approver, actor, true).insert_into(&mut payload.summary);
        if let Err(store_err) = self.store.append_audit_terminal(payload, None, None) {
            tracing::error!(
                approval_id = %approval.id,
                error = %store_err,
                "the terminal audit event for a failed approval resolution is not durable"
            );
        }
        approval.status = APPROVAL_UNRESOLVED.into();
        if let Err(store_err) = self.settle_approval(approval.clone()) {
            tracing::error!(
                approval_id = %approval.id,
                error = %store_err,
                "an approval whose resolution failed could not be marked unresolved; its claim is spent, so it cannot be resolved again"
            );
        }
        error
    }

    /// Resolve a pending approval, the second half of the human-in-the-loop.
    ///
    /// On **approve**, the originally-held capability is executed *now* (the policy
    /// already classified it as allowed-but-requiring-a-human), its redacted result is
    /// stored on the approval, and an `approved` audit event is appended, so the agent
    /// can poll `permaura.get_approval_status` and collect the result it was waiting on.
    /// On **deny**, a `denied` audit event is appended and no upstream call is ever made.
    /// Idempotent: resolving an already-resolved approval returns it unchanged.
    /// Concurrent resolutions are arbitrated by a durable claim. If execution or recording fails
    /// after claiming, retries are refused: an upstream write may already have happened, so an
    /// operator must inspect its outcome before requesting a new action.
    ///
    /// `method` records HOW the approval was resolved in the audit chain: `"device_signed"`
    /// (with `approver` = the verified approver id, e.g. `device:<id>`) or `"bearer"` (with
    /// `approver` = the operator session's identity). This is the one place the signed-vs-bearer
    /// distinction is preserved; without it the audit log cannot tell a cryptographically-signed
    /// refund from one waved through on a session cookie. The approving device's name is snapshotted
    /// beside the id; see [`ApproverDetail`].
    pub async fn resolve_approval(
        &self,
        approval_id: &str,
        approve: bool,
        method: &str,
        approver: Option<&str>,
    ) -> Result<PendingApproval, GatewayError> {
        self.resolve_approval_as(approval_id, approve, method, approver, None).await
    }

    /// [`Self::resolve_approval`], and whether it reached the approval's durable claim. An error short of the claim leaves the approval as approvable as it was; after one at or past it the claim may be spent, which the row does not show.
    pub async fn resolve_approval_reaching_claim(
        &self,
        approval_id: &str,
        approve: bool,
        method: &str,
        approver: Option<&str>,
    ) -> (Result<PendingApproval, GatewayError>, bool) {
        let mut claimed = false;
        let resolved = self.resolve_approval_claiming(approval_id, approve, method, approver, None, &mut claimed).await;
        (resolved, claimed)
    }

    /// [`Self::resolve_approval`], naming the workspace member behind a bearer resolution for the
    /// audit chain. `actor` is display only and changes nothing about whether or how the approval
    /// resolves.
    pub async fn resolve_approval_as(
        &self,
        approval_id: &str,
        approve: bool,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
    ) -> Result<PendingApproval, GatewayError> {
        self.resolve_approval_claiming(approval_id, approve, method, approver, actor, &mut false).await
    }

    async fn resolve_approval_claiming(
        &self,
        approval_id: &str,
        approve: bool,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
        claimed: &mut bool,
    ) -> Result<PendingApproval, GatewayError> {
        let mut approval = self
            .store
            .get_approval(approval_id)?
            .ok_or_else(|| GatewayError::NotFound(format!("approval '{approval_id}'")))?;

        // Already resolved → return as-is (a second tap must not re-run the action).
        if approval.status != "pending" {
            return Ok(approval);
        }
        // An approve of an approval this process is already resolving waits for no room or slot below: the first holds what it would wait for, and the wait would hold every agent call queued behind it until the claim refuses it.
        let again = approve && self.executions.is_resolving(approval_id);
        // Before the claim, so an approve a stopping gateway refuses is still pending and can be given
        // again once it is back. A denial runs nothing and is not an execution.
        let permit = if approve { Some(self.executions.admit(Some(approval_id))?) } else { None };

        // The execution hold, before the durable claim below, so a refusal writes nothing.
        //
        // Two things are deliberately still resolvable while held. A DENIAL runs nothing upstream,
        // and refusing it would strand every held call a reconciling owner wants to clear. And a
        // held POLICY_WRITE_CAP mutation IS a control-plane mutation (applying the stored diff is
        // the whole of it), which the contract keeps working while held, because reconciliation is
        // a sequence of control-plane mutations. Everything else here ends in `execute_allowed`.
        // Only the gateway's own control-plane path raises these, with no requesting session; an agent
        // call under the same capability id is a connector call and takes the capability path below.
        let held_change = approval.capability == crate::rest::POLICY_WRITE_CAP && approval.session_id.is_empty();
        let held_export = approval.capability == crate::rest::VAULT_EXPORT_CAP && approval.session_id.is_empty();
        if approve && held_change && approval.is_expired(now_ms()) {
            return Err(GatewayError::BadRequest(format!(
                "approval '{approval_id}' expired before anyone confirmed it; ask for the change again"
            )));
        }
        if approve && !held_change {
            self.refuse_if_held()?;
        }
        // An unheld change is classified and applied under the control-plane lock, so a held one is re-checked, claimed
        // and applied under it too. Otherwise each could be judged on an estate the other was about to move, and
        // together lower a rule that neither lowers alone. Held to the end of this call, past the apply below.
        let _control_plane = if approve && held_change { Some(self.control_plane_lock.lock().await) } else { None };
        if approve && held_change {
            approval = self.store.get_approval(approval_id)?.ok_or_else(|| GatewayError::NotFound(format!("approval '{approval_id}'")))?;
            if approval.status != "pending" {
                return Ok(approval);
            }
            if approval.is_expired(now_ms()) {
                return Err(GatewayError::BadRequest(format!("approval '{approval_id}' expired before anyone confirmed it; ask for the change again")));
            }
            if method == "device_signed" && !approver.is_some_and(|id| self.approver_keyring_snapshot().trusted_key(id).is_some()) {
                return Err(GatewayError::Denied("the confirming device is no longer trusted; the change stays pending".into()));
            }
        }
        // Before the claim, so a change short of the signatures it needs today stays pending. The marks it lowers are
        // read here too, under the same lock, since nothing past the claim may wait.
        let mut lowered = Vec::new();
        if approve && held_change {
            if let Ok(mutation) = serde_json::from_str::<crate::policy_guard::Mutation>(approval.params.get()) {
                let kept = self.kept_effect(&approval.id)?;
                let (quorum, below, now) = self.held_change_bar(&mutation, true, kept.as_ref().map(|r| &r.effect)).await?;
                self.refuse_short_of(&approval, method, Rung::DeviceSigned, quorum)?;
                // A change signed against one estate and applied to another can lower what another change unmasked in
                // between, with every signature it needs: a quorum of one asks nothing more of it. So it applies only
                // while it lowers nothing beyond what it lowered when it was held. A change whose own row has moved is
                // refused by the apply, which records which row.
                let moved = crate::rest::held_row_moved(self.store.as_ref(), &mutation, &approval.params)?;
                if let Some(why) = effect_widened(kept.as_ref(), &now).filter(|_| !moved) {
                    tracing::info!(approval_id = %approval.id, %why, "a held change whose effect grew after it was held was retired");
                    *claimed = self.retire_widened_hold(approval.clone())?;
                    return Err(GatewayError::Conflict(format!(
                        "approval '{}' was not applied: {why}. Its effect can no longer be verified against what was held, so ask for it again.",
                        approval.id
                    )));
                }
                lowered = below;
            }
        }
        // A held call is an invoke that has not run yet, so the pause and the bar its action is held
        // at now apply to it as they would to the call made again; the rest is re-checked past the claim.
        if approve && !held_change && !held_export {
            self.refuse_if_agents_paused()?;
            if self.is_paused() {
                return Err(GatewayError::Denied(
                    "All agents are paused by the operator; resume them before approving a held call.".into(),
                ));
            }
            if let Some((rung, quorum)) = self.current_bar(&approval)? {
                self.refuse_short_of(&approval, method, rung, quorum)?;
            }
        }

        // The held call's params as the execution needs them, parsed under the memory budget, and the execution slot it runs under if it needs one, both before the claim, so a refusal leaves the approval pending for the approver to try again. A slot goes with the params into the execution's task, as an unheld call's does.
        let held_params = if approve && !held_change && !held_export {
            let slot = self.approved_call_slot(&approval.params, again).await?;
            let wait = if again { std::time::Duration::ZERO } else { self.memory.wait() };
            Some(self.memory.parse_held(&approval.params, slot, wait).await?)
        } else {
            None
        };

        // Reading "pending" is not a claim: two requests (or two hosted instances) can both read it
        // before either records a result. Claim before any decision/effect, and never release on an
        // error: a failed response or audit write cannot prove that an upstream effect did not occur.
        // The replay floor, immediately before the claim. A restored database brings back every
        // approval the checkpoint held, pending again, with its resolution claim rolled back: a
        // signature given before the restore would otherwise release a held call a second time.
        crate::restore::refuse_if_replayed_across_a_restore(
            self.store.as_ref(),
            approval.created_at,
            "approval",
        )?;
        *claimed = true;
        if !self.store.claim_once("approval-resolution", approval_id, i64::MAX)? {
            return Err(GatewayError::BadRequest(format!(
                "approval '{approval_id}' is already claimed; inspect its status and the upstream \
                 outcome before requesting another action"
            )));
        }

        // Held control-plane mutation: there is no agent session or
        // upstream capability to run: applying the stored mutation IS the effect. Only a device
        // signature reaches here (these are minted `device_signed`-tier, so the bearer path is
        // refused), i.e. the operator has cryptographically confirmed this exact diff.
        if held_change {
            if approve {
                // The same rule as the capability path below, in its synchronous shape: past the
                // claim, every exit records. There is no await between here and `settle_approval`,
                // so a dropped request cannot interrupt this branch and it needs no task.
                let applied = serde_json::from_str(approval.params.get())
                    .map_err(|e| {
                        GatewayError::Internal(format!("held mutation could not be decoded: {e}"))
                    })
                    .and_then(|mutation: crate::policy_guard::Mutation| {
                        crate::rest::apply_held_mutation(self.store.as_ref(), self, &mutation, &approval.params)
                    });
                let applied = match applied {
                    Ok(applied) => applied,
                    Err(e) => {
                        // The claim is spent, so nothing can apply this change later: release what it parked.
                        if let Ok(mutation) = serde_json::from_str::<crate::policy_guard::Mutation>(approval.params.get()) {
                            crate::rest::cleanup_denied_mutation(self.store.as_ref(), &mutation);
                        }
                        return Err(self.unresolve(&mut approval, method, approver, actor, e));
                    }
                };
                if let Err(e) = self.settle_quorum_marks(&lowered, approval.required_signatures) {
                    // Failing safe: an unsettled mark only asks the next change for more people.
                    tracing::error!(approval = %approval.id, error = %e, "a quorum high-water mark the signers met was not cleared");
                }
                if let Err(e) =
                    self.audit_mutation("approved", &approval, method, approver, actor, Some(&applied))
                {
                    // The mutation landed and its record did not, which is the one direction that
                    // cannot be walked back: the store is quarantined, so the second append will
                    // fail too, and `unresolve` says so rather than pretending.
                    return Err(self.unresolve(&mut approval, method, approver, actor, e));
                }
                approval.status = "approved".into();
                approval.result = Some(JsonText::from_value(&applied));
            } else {
                // Release any resource the held mutation reserved but never applied, e.g. the
                // sealed staging secret a `CredentialPromote` parked. Best-effort.
                if let Ok(mutation) =
                    serde_json::from_str::<crate::policy_guard::Mutation>(approval.params.get())
                {
                    crate::rest::cleanup_denied_mutation(self.store.as_ref(), &mutation);
                }
                self.audit_mutation("denied", &approval, method, approver, actor, None)?;
                approval.status = "denied".into();
            }
            let id = approval.id.clone();
            let answered = self.settle_and_answer(approval);
            self.forget_kept_effect(&id);
            return answered;
        }

        // A held vault export. Unlike a held mutation, approving APPLIES NOTHING: the signature
        // authorises an export, and the bundle is produced when the client comes back with this
        // approval id. It has to work that way, because the passphrase that seals the bundle is
        // deliberately not stored on the approval, so there is nothing here to replay it from.
        // Like the mutation branch, this exists because a held export has no agent session and no
        // connector capability, and the lookups below would fail on both.
        if held_export {
            let decision = if approve { "approved" } else { "denied" };
            if let Err(e) = self.audit_mutation(decision, &approval, method, approver, actor, None) {
                return Err(self.unresolve(&mut approval, method, approver, actor, e));
            }
            approval.status = decision.into();
            return self.settle_and_answer(approval);
        }

        let Some(session) = self.store.get_session(&approval.session_id)? else {
            return self.end_hold_that_cannot_run(approval, None, approve, method, approver, actor);
        };
        let Some(cap) = self.store.get_capability(&approval.capability)? else {
            return self.end_hold_that_cannot_run(approval, Some(&session), approve, method, approver, actor);
        };

        if approve {
            // Re-validate the gates at approval time. A held call must not execute if the world
            // changed underneath it: the session that made it revoked or expired, the capability
            // switched off, its connection removed, the agent revoked/un-approved, the policy edited
            // to deny, or the grant expired / ran out of budget (e.g. another held call for the same
            // max_calls=1 grant already ran). Without this, approving a stale hold bypasses every
            // grant limit.
            let Some(held_params) = held_params else {
                return Err(GatewayError::Internal(format!("approval '{}' has no parsed params to run", approval.id)));
            };
            let recheck = self.recheck_held_call(&session, &cap, &approval, &held_params)?;
            let (redact_keys, reservation, grant_id, policy_id) = match recheck {
                HeldRecheck::Allowed { redact_keys, reservation, grant_id, policy_id } => {
                    (redact_keys, reservation, grant_id, policy_id)
                }
                HeldRecheck::Denied { why, resolution_reason } => {
                    // `denied` is the gateway's verdict, not the human's, and `approver` names someone
                    // who said yes; `human_decision` is what stops a reader naming them as the one who
                    // refused.
                    let mut summary = serde_json::json!({
                        "approval_id": approval.id,
                        "reason": format!("re-validation failed at approval time: {why}"),
                        "human_decision": "approved",
                        "method": method,
                        "approver": approver,
                    });
                    self.approver_detail(&approval, method, approver, actor, true).insert_into(&mut summary);
                    self.audit(&session, &cap, "denied", ExecutionLocation::LocalOnly, summary)?;
                    approval.status = "denied".into();
                    approval.resolution_reason = resolution_reason.map(str::to_string);
                    return self.settle_and_answer(approval);
                }
            };
            // The durable `attempt` `invoke` writes before the credential is used, so a held call whose
            // worker is killed mid-flight still leaves a record that it was released. Not gated on the
            // audit ceiling: a human clearing held calls is the remedy for that pressure. A failed
            // append ran nothing, which is what `unresolve` records.
            let mut summary = serde_json::json!({
                "approval_id": approval.id,
                "grant_id": grant_id,
                "policy_id": policy_id,
                "method": method,
                "approver": approver,
            });
            if grant_id != approval.grant_id {
                summary["held_grant_id"] = approval.grant_id.clone().into();
            }
            self.approver_detail(&approval, method, approver, actor, true).insert_into(&mut summary);
            if let Err(e) = self.audit(&session, &cap, "attempt", ExecutionLocation::LocalOnly, summary) {
                return Err(self.unresolve(&mut approval, method, approver, actor, e));
            }
            // ── Past here the execution has begun, and exactly one terminal event follows it. ──
            //
            // The claim above is already spent, so from this point nothing can make the call not
            // have been attempted. Before this, an error out of `execute_allowed` returned straight
            // to the caller: the claim was spent, the upstream may well have landed, the approval
            // stayed `pending` and the chain said nothing at all. That is the one state an auditor
            // cannot distinguish from a call that was never made, on the one path where a human had
            // just said yes.
            //
            // The same design `invoke` got: the execution and its terminal append run in a task of
            // their own and this future only awaits the handle, so dropping this future (the
            // inbound request timeout, an approver's phone losing the network) cancels nothing and
            // the task records what the call actually did. Nothing can recall a request already
            // sent, so finishing it is the only version that learns the answer.
            //
            // The task also settles the row, on success as on failure. Settling it here after the
            // await left an approval whose approver hung up mid-call with its claim spent, its
            // `approved` event written and its row still `pending`, so every later approve was
            // refused as already claimed and the agent never collected a result that existed.
            let approval_id = approval.id.clone();
            let trace = Arc::new(ExecutionTrace::new());
            let executed = {
                let service = self.clone();
                let mut terminal = TerminalEvent {
                    store: self.store.clone(),
                    session: session.clone(),
                    cap: cap.clone(),
                    execution_location: ExecutionLocation::LocalOnly,
                    intent: None,
                    grant_id,
                    policy_id,
                    approval: Some(ApprovalContext {
                        id: approval.id.clone(),
                        method: method.to_string(),
                        approver: approver.map(str::to_string),
                        detail: self.approver_detail(&approval, method, approver, actor, true),
                    }),
                    execution_id: None,
                    trace: trace.clone(),
                    armed: true,
                };
                let cap = cap.clone();
                let mut params = held_params;
                let mut settled = approval;
                tokio::spawn(async move {
                    let _permit = permit;
                    // The recheck read the session before the attempt was recorded, and on a hosted
                    // store that append is an upload, so a revocation can land in between. Nothing
                    // has been sent yet, so it still stops the call.
                    match service.held_session_lapse(&terminal.session.id, settled.created_at) {
                        Ok(None) => {}
                        Ok(Some(why)) => {
                            terminal.record_session_ended(why)?;
                            params.drop_tree();
                            settled.status = "denied".into();
                            settled.resolution_reason = Some(DENIED_SESSION_ENDED.to_string());
                            return service.settle_and_answer(settled);
                        }
                        Err(e) => {
                            if let Err(store_err) = terminal.record_refused_at_fence(&e) {
                                tracing::error!(
                                    approval_id = %settled.id,
                                    error = %store_err,
                                    "the terminal audit event for a held call refused before it ran is not durable"
                                );
                            }
                            params.drop_tree();
                            settled.status = APPROVAL_UNRESOLVED.into();
                            let id = settled.id.clone();
                            if let Err(store_err) = service.settle_approval(settled) {
                                tracing::error!(
                                    approval_id = %id,
                                    error = %store_err,
                                    "an approval refused before it ran could not be marked unresolved; its claim is spent, so it cannot be resolved again"
                                );
                            }
                            return Err(e);
                        }
                    }
                    // The row's copy of the params is not held while the call runs; it is written back from the tree, as serde_json wrote it when the call was held, before the tree is dropped and the row stored ([`crate::memory::held_room`]).
                    drop(std::mem::take(&mut settled.params));
                    let executed = service.execute_allowed(&cap, &params, &redact_keys, &trace).await;
                    settled.params = JsonText::from_value(params.value());
                    params.drop_tree();
                    match executed {
                        Ok(executed) => {
                            terminal.record_approved(&executed)?;
                            // Released once the terminal append has charged the grant, never before
                            // it, and not held across the row write either: on a hosted store that
                            // write can wait on an upload, and a reservation still standing beside the
                            // charge counts this call twice against the grant.
                            drop(reservation);
                            settled.status = "approved".into();
                            settled.result = Some(executed.redacted);
                            settled.result_status = Some(executed.status);
                            service.settle_and_answer(settled)
                        }
                        Err(e) => {
                            // The chain first, because it is the durable record and the row is a
                            // view of it. The caller is told what happened to THEIR call, so the
                            // execution error wins over a failure to record it.
                            if let Err(store_err) = terminal.record_error(&e) {
                                tracing::error!(
                                    approval_id = %settled.id,
                                    capability = %cap.id,
                                    error = %store_err,
                                    "the terminal audit event for a failed approval resolution is not durable"
                                );
                            }
                            // The row stops saying `pending`, which would leave a question on an
                            // operator's dashboard that has in fact been answered, and stops the
                            // control plane waiting. It does NOT say `denied`: a denial claims
                            // nothing ran, and something may well have.
                            settled.status = APPROVAL_UNRESOLVED.into();
                            let id = settled.id.clone();
                            if let Err(store_err) = service.settle_approval(settled) {
                                tracing::error!(
                                    approval_id = %id,
                                    error = %store_err,
                                    "an approval whose execution failed could not be marked unresolved; its claim is spent, so it cannot be resolved again"
                                );
                            }
                            Err(e)
                        }
                    }
                })
            };
            return match executed.await {
                Ok(result) => result,
                // The task is never aborted, so this is a panic inside the connector path (the
                // guard has already written the terminal event on the way out) or a runtime
                // shutting down underneath it. The row is still `pending` in that case, and the
                // spent claim is what stops it running again.
                Err(join) => Err(GatewayError::Internal(format!(
                    "the execution task for approval '{approval_id}' did not finish: {join}"
                ))),
            };
        } else {
            let mut summary = serde_json::json!({
                "approval_id": approval.id,
                "reason": "denied by human approver",
                "method": method,
                "approver": approver,
            });
            self.approver_detail(&approval, method, approver, actor, false).insert_into(&mut summary);
            self.audit(&session, &cap, "denied", ExecutionLocation::LocalOnly, summary)?;
            approval.status = "denied".into();
        }

        self.settle_and_answer(approval)
    }

    /// Settle every approval an earlier process of this gateway left claimed and unfinished.
    ///
    /// Two shapes, both found from the pending rows and read against the audit chain, which is the
    /// record the row is a view of:
    ///
    /// - **An `attempt` and nothing after it.** The process was killed, crashed or ran out of drain
    ///   window while the held call was running, so the call may have landed. One terminal `error` is
    ///   appended, outcome `unknown` and kind `interrupted`, carrying the approver the `attempt`
    ///   names, and the row moves to [`APPROVAL_UNRESOLVED`]. Its claim stays spent, so nothing runs
    ///   again. One older than `min_age` only; the rest are counted in `deferred`.
    /// - **A terminal event with the row still `pending`.** The process stopped between the chain and
    ///   the row, or the execution task was dropped and its guard wrote the event. The row is made to
    ///   say what the chain says and nothing is appended.
    ///
    /// Only events below `recorded_before` count, which is the chain's length when this process
    /// began serving: whatever this process records about its own executions it also settles itself,
    /// so the only endings missing are ones an earlier process owed. Approvals this process is
    /// resolving right now are skipped for the same reason, and an approval with neither shape is
    /// left alone: it is still a question. Nothing is executed on any path.
    pub fn settle_interrupted_approvals(
        &self,
        min_age: std::time::Duration,
        recorded_before: u64,
    ) -> Result<InterruptedSettlement, GatewayError> {
        let mut report = InterruptedSettlement::default();
        let in_flight = self.executions.in_flight_approvals();
        let pending: Vec<PendingApproval> = self
            .store
            .list_approvals(Some("pending"))?
            .into_iter()
            .filter(|a| !in_flight.contains(&a.id))
            .collect();
        if pending.is_empty() {
            return Ok(report);
        }

        #[derive(Default)]
        struct Track {
            attempt: Option<permaura_core::AuditEvent>,
            terminal: Option<permaura_core::AuditEvent>,
        }
        let mut tracks: std::collections::HashMap<String, Track> =
            pending.iter().map(|a| (a.id.clone(), Track::default())).collect();
        const PAGE: usize = 500;
        let mut from = 0u64;
        loop {
            let page = self.store.audit_events_from(from, PAGE)?;
            let complete = page.len() < PAGE;
            let Some(next) = page.last().map(|e| e.seq + 1) else { break };
            for event in page {
                let Some(id) = event.payload.summary.get("approval_id").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(track) = tracks.get_mut(id) else { continue };
                match event.payload.decision.as_str() {
                    "attempt" => track.attempt = Some(event),
                    "approved" | "denied" | "error" => track.terminal = Some(event),
                    _ => {}
                }
            }
            if complete {
                break;
            }
            from = next;
        }

        let now = now_ms();
        let min_age_ms = i64::try_from(min_age.as_millis()).unwrap_or(i64::MAX);
        for mut approval in pending {
            let Some(track) = tracks.remove(&approval.id) else { continue };
            if let Some(terminal) = track.terminal {
                if terminal.seq >= recorded_before {
                    continue;
                }
                match terminal.payload.decision.as_str() {
                    "approved" => {
                        approval.status = "approved".into();
                        approval.result_status = terminal
                            .payload
                            .summary
                            .get("status")
                            .and_then(|v| v.as_u64())
                            .and_then(|v| u16::try_from(v).ok());
                    }
                    "denied" => approval.status = "denied".into(),
                    _ => approval.status = APPROVAL_UNRESOLVED.into(),
                }
                report.reconciled.push(approval.id.clone());
                self.settle_approval(approval)?;
                continue;
            }
            let Some(attempt) = track.attempt.filter(|a| a.seq < recorded_before) else { continue };
            let age = now.saturating_sub(attempt.timestamp);
            if age < min_age_ms {
                report.deferred += 1;
                let wait = std::time::Duration::from_millis(u64::try_from(min_age_ms - age).unwrap_or(0));
                report.retry_in = Some(report.retry_in.map_or(wait, |w| w.min(wait)));
                continue;
            }
            let fence = &attempt.payload.summary;
            let mut summary = serde_json::json!({
                "ok": false,
                "outcome": ExecutionOutcome::Unknown.as_str(),
                "error_kind": INTERRUPTED_ERROR_KIND,
                "dispatched": serde_json::Value::Null,
                "intent": serde_json::Value::Null,
                "grant_id": fence.get("grant_id").cloned().unwrap_or(serde_json::Value::Null),
                "policy_id": fence.get("policy_id").cloned().unwrap_or(serde_json::Value::Null),
                "approval_id": approval.id,
                "method": fence.get("method").cloned().unwrap_or(serde_json::Value::Null),
                "approver": fence.get("approver").cloned().unwrap_or(serde_json::Value::Null),
            });
            for key in ["approver_name", "approver_actor", "signers"] {
                if let Some(value) = fence.get(key) {
                    summary[key] = value.clone();
                }
            }
            let mut payload = attempt.payload.clone();
            payload.decision = "error".into();
            payload.summary = summary;
            let charge = crate::store::charge_of(&payload);
            // A store that cannot make it durable may still hold it locally, and then the next pass
            // finds the terminal event and settles the row from it; the row waits so the two agree.
            if let Err(e) = self.store.append_audit_terminal(payload, charge, None) {
                tracing::error!(
                    approval_id = %approval.id,
                    error = %e,
                    "the terminal audit event for an interrupted approval is not durable; its row stays pending until it is"
                );
                continue;
            }
            approval.status = APPROVAL_UNRESOLVED.into();
            report.interrupted.push(approval.id.clone());
            self.settle_approval(approval)?;
        }
        Ok(report)
    }

    /// Close every `invoke` an earlier process left with an `attempt` and no terminal event, as [`Self::settle_interrupted_approvals`] does for a held call.
    ///
    /// One `error` with outcome `unknown` and kind `interrupted` per attempt, paired by the `execution_id` both carry and charged to the attempt's grant, since nothing can rule out that the call was sent: a process that died between dispatch and its terminal append would otherwise hand the budget back. Attempts at or past `recorded_before` belong to this process, and one younger than `min_age` is counted in `deferred`. Nothing is run again.
    pub fn settle_interrupted_invokes(
        &self,
        min_age: std::time::Duration,
        recorded_before: u64,
    ) -> Result<InterruptedSettlement, GatewayError> {
        let mut report = InterruptedSettlement::default();
        let mut open: std::collections::BTreeMap<String, permaura_core::AuditEvent> = std::collections::BTreeMap::new();
        const PAGE: usize = 500;
        let mut from = 0u64;
        loop {
            let page = self.store.audit_events_from(from, PAGE)?;
            let complete = page.len() < PAGE;
            let Some(next) = page.last().map(|e| e.seq + 1) else { break };
            for event in page {
                let Some(id) = event.payload.summary.get("execution_id").and_then(|v| v.as_str()).map(str::to_string) else {
                    continue;
                };
                if event.payload.decision != "attempt" {
                    open.remove(&id);
                } else if event.seq < recorded_before {
                    open.insert(id, event);
                }
            }
            if complete {
                break;
            }
            from = next;
        }

        let now = now_ms();
        let min_age_ms = i64::try_from(min_age.as_millis()).unwrap_or(i64::MAX);
        for (execution_id, attempt) in open {
            let age = now.saturating_sub(attempt.timestamp);
            if age < min_age_ms {
                report.deferred += 1;
                let wait = std::time::Duration::from_millis(u64::try_from(min_age_ms - age).unwrap_or(0));
                report.retry_in = Some(report.retry_in.map_or(wait, |w| w.min(wait)));
                continue;
            }
            let fence = &attempt.payload.summary;
            let field = |key: &str| fence.get(key).cloned().unwrap_or(serde_json::Value::Null);
            let mut payload = attempt.payload.clone();
            payload.decision = "error".into();
            payload.summary = serde_json::json!({
                "ok": false,
                "outcome": ExecutionOutcome::Unknown.as_str(),
                "error_kind": INTERRUPTED_ERROR_KIND,
                "dispatched": serde_json::Value::Null,
                "intent": field("intent"),
                "grant_id": field("grant_id"),
                "policy_id": field("policy_id"),
                "execution_id": execution_id,
            });
            let charge = crate::store::charge_of(&payload);
            if let Err(e) = self.store.append_audit_terminal(payload, charge, None) {
                tracing::error!(
                    execution_id = %execution_id,
                    error = %e,
                    "the terminal audit event for an interrupted execution is not durable; the next boot settles it"
                );
                continue;
            }
            report.invokes.push(execution_id);
        }
        Ok(report)
    }

    /// Executions an earlier process began and never closed, from the chain below `recorded_before`: each `attempt` that carries a grant id and has no terminal event yet, by [`open_execution_key`], with the grant and agent its charge will be filed under. A held call counts only while its approval is still pending, the ones [`Self::settle_interrupted_approvals`] settles.
    fn open_executions(&self, recorded_before: u64) -> Result<std::collections::BTreeMap<String, (String, String)>, GatewayError> {
        let pending: std::collections::HashSet<String> =
            self.store.list_approvals(Some("pending"))?.into_iter().map(|a| a.id).collect();
        let mut open = std::collections::BTreeMap::new();
        const PAGE: usize = 500;
        let mut from = 0u64;
        loop {
            let page = self.store.audit_events_from(from, PAGE)?;
            let complete = page.len() < PAGE;
            let Some(next) = page.last().map(|e| e.seq + 1) else { break };
            for event in page {
                let Some(key) = open_execution_key(&event.payload) else { continue };
                if event.payload.decision != "attempt" {
                    open.remove(&key);
                    continue;
                }
                let held_call_settles = event.payload.summary.get("approval_id").and_then(|v| v.as_str()).is_none_or(|id| pending.contains(id));
                let grant = event.payload.summary.get("grant_id").and_then(|v| v.as_str());
                if let (true, true, Some(grant)) = (event.seq < recorded_before, held_call_settles, grant) {
                    open.insert(key, (grant.to_string(), crate::store::charge_agent(&event.payload).to_string()));
                }
            }
            if complete {
                break;
            }
            from = next;
        }
        Ok(open)
    }

    /// Hold the grant budget of every execution an earlier process began and never closed, until the boot settlement charges it.
    ///
    /// Run before the gateway serves anything. The reservation an execution holds in [`BudgetBook`] dies with its process, and the settlement that charges its attempt waits [`crate::drain::SETTLE_AFTER_BOOT`], and on a hosted worker until the attempt is older than the execution ceiling, so without this a call retried right after a crash or a rollout read an empty book and a counter that did not count the call already sent, and reached the upstream past `max_calls`. Returns how many it holds.
    pub fn carry_interrupted_budget(&self, recorded_before: u64) -> Result<usize, GatewayError> {
        let open = self.open_executions(recorded_before)?;
        let mut book = crate::store::bridge::lock_donating(&self.budget_book).unwrap_or_else(|e| e.into_inner());
        for (key, (grant_id, agent_id)) in &open {
            book.carry(key.clone(), grant_id, agent_id);
        }
        Ok(open.len())
    }

    /// Give back the budget [`Self::carry_interrupted_budget`] held for each execution the chain now closes, once the terminal event that charged the counter is in, so a concurrent call sees it either way.
    pub fn release_settled_budget(&self, recorded_before: u64) -> Result<(), GatewayError> {
        let open = self.open_executions(recorded_before)?;
        let mut book = crate::store::bridge::lock_donating(&self.budget_book).unwrap_or_else(|e| e.into_inner());
        let settled: Vec<String> = book.carried.keys().filter(|key| !open.contains_key(*key)).cloned().collect();
        for key in settled {
            book.release_carried(&key);
        }
        Ok(())
    }

    /// The rung and quorum the engine puts on a held call's action now, or `None` when it would deny
    /// the call or its session or capability is gone: [`Self::recheck_held_call`] or
    /// [`Self::end_hold_that_cannot_run`] then says why.
    /// Budget is left out; the recheck past the claim applies it.
    fn current_bar(&self, approval: &PendingApproval) -> Result<Option<(Rung, u8)>, GatewayError> {
        let (Some(session), Some(cap)) =
            (self.store.get_session(&approval.session_id)?, self.store.get_capability(&approval.capability)?)
        else {
            return Ok(None);
        };
        let input = DecisionInput {
            capability_id: cap.id.split_once('.').map_or_else(|| cap.id.clone(), |(_, rest)| rest.to_string()),
            action: cap.action,
            connection_id: cap.resource.clone(),
            risk: cap.risk,
            capability_requires_approval: cap.requires_approval,
            agent_id: session.agent_id.clone(),
            context: RequestContext::new(session.id.clone(), OffsetDateTime::now_utc()),
        };
        let engine = PolicyEngine::with(self.store.list_grants()?, self.store.policies_for_connection(&cap.resource)?);
        let resolution = engine.resolve(&input, &permaura_policy::Unmetered);
        Ok((resolution.decision.kind != DecisionKind::Deny).then_some((resolution.rung, resolution.quorum)))
    }

    /// Why the session `session_id` names no longer stands behind a call it held at `held_at`, read
    /// fresh from the store, or `None` while it does.
    fn held_session_lapse(&self, session_id: &str, held_at: i64) -> Result<Option<&'static str>, GatewayError> {
        match self.store.get_session(session_id)? {
            Some(session) => self.hold_lapse(&session, held_at, now_ms()),
            None => Ok(Some(SESSION_GONE)),
        }
    }

    /// Why `session` no longer stands behind a call it held at `held_at` (unix ms), or `None` while it does: the row revoked or expired, a bearer that opened it ended ([`Self::opener_lapse`]), or its agent admitted again since.
    ///
    /// An OAuth agent's row keeps one id across its owner removing it and letting the same client back in, so the
    /// hold is bound to the agent's admission, not to the row: a removal deletes the agent and a readmission enrols it
    /// afresh, while the refresher pruning the row for age and the client's next call writing a new one leave the agent,
    /// and its holds, as they were. A hold stored before its creation time was recorded (`held_at` zero) is judged on
    /// the row alone.
    fn hold_lapse(&self, session: &Session, held_at: i64, now: i64) -> Result<Option<&'static str>, GatewayError> {
        if let Some(why) = session_lapse(session, now) {
            return Ok(Some(why));
        }
        // A bearer that opened this session stands behind the calls it held as it stands behind the session itself.
        if let Some(why) = self.opener_lapse(session, now)? {
            return Ok(Some(why));
        }
        let readmitted = self.store.get_agent(&session.agent_id)?.is_some_and(|a| held_at > 0 && a.enrolled_at > held_at);
        Ok(readmitted.then_some("its agent was removed and admitted again since the call was held"))
    }

    /// Settle a hold with nothing left to run it: its session row is gone (`session` is `None`; the
    /// sweep deletes a revoked row a week after its last use), or its capability row is (deleting its
    /// connection deletes them). The lookup error this replaces stranded the hold pending with its
    /// claim spent.
    fn end_hold_that_cannot_run(
        &self,
        mut approval: PendingApproval,
        session: Option<&Session>,
        approve: bool,
        method: &str,
        approver: Option<&str>,
        actor: Option<&crate::store::SessionActor>,
    ) -> Result<PendingApproval, GatewayError> {
        let (why, resolution_reason) = match session {
            None => (SESSION_GONE, Some(DENIED_SESSION_ENDED)),
            Some(_) => ("its capability does not exist", None),
        };
        let mut summary = if approve {
            serde_json::json!({
                "approval_id": approval.id,
                "reason": format!("re-validation failed at approval time: {why}"),
                "human_decision": "approved",
                "method": method,
                "approver": approver,
            })
        } else {
            serde_json::json!({
                "approval_id": approval.id,
                "reason": "denied by human approver",
                "method": method,
                "approver": approver,
            })
        };
        self.approver_detail(&approval, method, approver, actor, approve).insert_into(&mut summary);
        let mut payload = AuditPayload::new(approval.capability.clone(), approval.resource.clone(), "denied");
        payload.session_id = Some(approval.session_id.clone());
        if let Some(session) = session {
            payload.user_id = session.user_id.clone();
            payload.agent_id = Some(session.agent_id.clone());
            payload.device_id = session.device_id.clone();
        }
        payload.execution_location = Some("local".to_string());
        payload.summary = summary;
        self.store.append_audit(payload)?;
        approval.status = "denied".into();
        if approve {
            approval.resolution_reason = resolution_reason.map(str::to_string);
        }
        self.settle_and_answer(approval)
    }

    /// Re-run the authorization gates for a held call at approval time. Returns
    /// [`HeldRecheck::Denied`] if the call should now be denied (and must not execute), or
    /// [`HeldRecheck::Allowed`] with the redaction set its result gets and the grant it is now
    /// authorized on, if it is still authorized.
    /// Mirrors [`Self::invoke`]'s pre-engine gates (the session live, which `invoke` has from
    /// [`Self::authenticate`], connection exists + enabled, agent approved) plus a fresh policy/grant
    /// resolution (which re-checks the policy's allow/deny, the grant's
    /// expiry, and its per-period call budget, so a hold cannot outrun a `max_calls` limit or
    /// survive a revoked grant / edited policy). The redaction set comes from that same fresh
    /// resolution, exactly as [`Self::invoke`] builds it for a call that runs at once.
    fn recheck_held_call(
        &self,
        session: &Session,
        cap: &Capability,
        approval: &PendingApproval,
        params: &serde_json::Value,
    ) -> Result<HeldRecheck, GatewayError> {
        if let Some(why) = self.hold_lapse(session, approval.created_at, now_ms())? {
            return Ok(HeldRecheck::Denied { why: why.to_string(), resolution_reason: Some(DENIED_SESSION_ENDED) });
        }
        let denied = |why: &str| Ok(HeldRecheck::Denied { why: why.to_string(), resolution_reason: None });
        let connection_id = &cap.resource;
        let connection = match self.store.get_connection(connection_id)? {
            None => return denied("its connection was removed"),
            Some(c) if c.disabled => return denied("its connection was disabled"),
            Some(c) if c.disabled_capabilities.iter().any(|x| x == &cap.id) => {
                return denied("the capability was switched off")
            }
            Some(c) => c,
        };
        if let Some(why) = self.connection_revocation(&connection)? {
            return denied(&format!("its connector was revoked: {why}"));
        }
        // Re-apply the generic-HTTP egress allowlist at approval time, so a held call cannot
        // outrun an allowlist the operator tightened (or that was empty) while it waited.
        if let Some(why) = egress_refusal(&connection, cap, params) {
            return Ok(HeldRecheck::Denied { why: format!("its egress check failed: {why}"), resolution_reason: None });
        }
        let approved = self
            .store
            .get_agent(&session.agent_id)?
            .map(|a| a.is_approved())
            .unwrap_or(false);
        if !approved {
            return denied("the agent is no longer approved");
        }
        let policy_action = cap
            .id
            .split_once('.')
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| cap.id.clone());
        let grants = self.store.list_grants()?;
        let policies = self.store.policies_for_connection(connection_id)?;
        let now = now_ms();
        let mut book = crate::store::bridge::lock_donating(&self.budget_book).unwrap_or_else(|e| e.into_inner());
        let usage = AuditUsage::measure(self.store.as_ref(), &grants, now)?.with_reserved(&book);
        let input = DecisionInput {
            capability_id: policy_action,
            action: cap.action,
            connection_id: connection_id.clone(),
            risk: cap.risk,
            capability_requires_approval: cap.requires_approval,
            agent_id: session.agent_id.clone(),
            context: RequestContext {
                session_id: session.id.clone(),
                requested_at: OffsetDateTime::now_utc(),
                execution_location: ExecutionLocation::LocalOnly,
                amount: params.get("amount").and_then(|v| v.as_f64()),
            },
        };
        let engine = PolicyEngine::with(grants.clone(), policies);
        let resolution = engine.resolve(&input, &usage);
        if resolution.decision.kind == DecisionKind::Deny {
            return Ok(HeldRecheck::Denied { why: resolution.decision.reason, resolution_reason: None });
        }
        // Reserve and charge the grant this resolution found headroom on, which need not be the one the hold recorded; charging any other lets a grant authorize calls it never pays for.
        let (grant_id, policy_id) = if resolution.matched_grant_id == approval.grant_id {
            (approval.grant_id.clone(), approval.policy_id.clone())
        } else {
            (resolution.matched_grant_id, resolution.matched_policy_id)
        };
        let reservation = grant_id
            .as_deref()
            .map(|grant| book.reserve(&self.budget_book, grant, &session.agent_id));
        drop(book);
        let redact_keys = self.redaction_for(&connection, cap, &resolution.redact_fields)?;
        Ok(HeldRecheck::Allowed { redact_keys, reservation, grant_id, policy_id })
    }

    /// The redaction set a call's result gets: the gateway defaults, the connection's own list, the
    /// list of the catalog manifest it was made from, the names the capability injects its credential
    /// under ([`Capability::credential_field_names`], so an imported `xi-api-key` header also redacts
    /// `xi_api_key`), and `policy_fields` (every policy that permitted the call, from the engine's
    /// resolution). Union only; see [`permaura_core::effective_redact_keys`]. Resolved per call rather
    /// than stored, so a connection made before its manifest gained a redaction still gets it, and an
    /// import, a re-sync or an operator's auth override is covered with no migration.
    fn redaction_for(
        &self,
        connection: &permaura_core::Connection,
        cap: &Capability,
        policy_fields: &[String],
    ) -> Result<Vec<String>, GatewayError> {
        let manifest =
            crate::presets::manifest_redact_fields(self.store.as_ref(), &connection.connector)?;
        let injected = cap.credential_field_names();
        Ok(permaura_core::effective_redact_keys(
            connection.redact_fields.iter().chain(&manifest).chain(&injected).chain(policy_fields),
        ))
    }

    /// A wall-clock ceiling over [`Self::execute_allowed_inner`].
    ///
    /// Every shipped connector already has a budget of its own (HTTP 30s, SSH 30s, a command 60s)
    /// and this default sits above all of them, so it never pre-empts a connector's own,
    /// better-worded timeout. It exists for the steps around them that have no budget: resolving a
    /// dynamic secret, unwrapping the vault, or a connector added later that forgets one.
    async fn execute_allowed(
        &self,
        cap: &Capability,
        params: &serde_json::Value,
        redact_keys: &[String],
        trace: &ExecutionTrace,
    ) -> Result<Executed, GatewayError> {
        let Some(budget) = crate::limits::execution_budget() else {
            return self.execute_allowed_inner(cap, params, redact_keys, trace).await;
        };
        match tokio::time::timeout(budget, self.execute_allowed_inner(cap, params, redact_keys, trace)).await {
            Ok(result) => result,
            Err(_) => Err(GatewayError::UpstreamTimeout(format!(
                "'{}' ran past the gateway's {}ms execution ceiling",
                cap.id,
                budget.as_millis()
            ))),
        }
    }

    /// Resolve the sealed secret, inject it inside the vault closure, run the capability,
    /// and redact the result with `redact_keys` (the call's effective set, see
    /// [`Self::redaction_for`]). The secret bytes never leave the closure: they are shaped
    /// into an HTTP header (for [`CapabilityKind::Http`]), a command env var (for
    /// [`CapabilityKind::Command`]) or an SSH credential, and dropped before we ever touch the
    /// network or spawn a child. Every kind shares the same vault discipline and the same redaction.
    ///
    /// This is the one place every agent execution opens its secret, so it is also where the
    /// [`CredentialScrub`] for the call is built from that plaintext: each kind scrubs its result
    /// before key-name redaction, and [`scrubbed`] then covers everything else the execution hands
    /// back, whichever kind produced it. The scrub is the one copy of the plaintext that outlives the
    /// opened handle: it stays inside the closure, is never sent anywhere, and zeroizes on drop once the
    /// result has been scrubbed.
    async fn execute_allowed_inner(
        &self,
        cap: &Capability,
        params: &serde_json::Value,
        redact_keys: &[String],
        trace: &ExecutionTrace,
    ) -> Result<Executed, GatewayError> {
        let prepared = match cap.kind {
            // The connection's family, not the capability id, decides how the request is shaped: a
            // capability made through a connection is namespaced by the connection id.
            CapabilityKind::Http => Prepared::Http(
                self.store.get_connection(&cap.resource)?.map(|c| c.connector).unwrap_or_default(),
            ),
            // Refused here as well as at creation, because a connection made before the gate existed,
            // or imported from a bundle, still has to be inert on a hosted worker.
            CapabilityKind::Command if self.hosted => return Err(GatewayError::Denied(
                "command capabilities do not run on a hosted gateway: the container has nothing to run and the credential would reach a child process".to_string(),
            )),
            CapabilityKind::Command => Prepared::Command(cap.command.clone().ok_or_else(|| {
                GatewayError::Internal(format!("capability '{}' is missing its command spec", cap.id))
            })?),
            CapabilityKind::Ssh => {
                let spec = cap.ssh.clone().ok_or_else(|| {
                    GatewayError::Internal(format!("capability '{}' is missing its ssh spec", cap.id))
                })?;
                // Refused here as well as at creation, so a connection stored before the screen existed, or imported, is held to it too.
                if self.hosted {
                    connectors::screen_host(&spec.target.host).map_err(|e| {
                        GatewayError::Denied(format!(
                            "a hosted gateway opens SSH sessions to public addresses only, so '{}' is refused ({e})",
                            spec.target.host
                        ))
                    })?;
                }
                Prepared::Ssh(spec)
            }
        };
        self.with_secret(&cap.secret_id, |opened| async move {
            let mut scrub = credential_scrub(opened.bytes());
            // Best effort, before the next future is made: see clear_stack for what it does and does not reach.
            permaura_core::secret::clear_stack();
            let outcome = match prepared {
                Prepared::Http(connector) => {
                    self.execute_http_with(&connector, cap, params, opened, &mut scrub, redact_keys, trace).await
                }
                Prepared::Command(spec) => {
                    self.execute_command_with(spec, params, opened, &scrub, redact_keys, trace).await
                }
                Prepared::Ssh(spec) => self.execute_ssh_with(spec, params, opened, &scrub, redact_keys, trace).await,
            };
            scrubbed(outcome, &scrub)
        })
        .await
    }

    /// The OAuth credential to send for this call: `opened` as it was read, or the stored bundle after
    /// a refresh when the access token is at or near expiry.
    ///
    /// Refreshes are coordinated per secret. An invocation that finds its credential expired
    /// takes the secret's slot, re-reads the stored record under it and, when another invocation has
    /// already rotated it, uses that rotation rather than sending the same one-use refresh token
    /// again. The refreshed bundle is written back only while the stored envelope is still the one the
    /// refresh started from ([`Store::put_secret_if_unchanged`]), so a BYO callback that completed a
    /// new authorization meanwhile keeps its result: the refresh is discarded and the invocation goes
    /// again with the replacement, once. Slots are per secret, so independent credentials refresh
    /// concurrently.
    ///
    /// Only the wait for the slot runs in the caller's future. The refresh round itself
    /// ([`Self::refresh_oauth_credential`]) runs in a detached task that owns the slot, because a
    /// provider that rotates on every refresh has consumed the old refresh token the moment it answers,
    /// whether or not anyone reads the answer: a caller that goes away mid-request (the inbound request
    /// timeout, an operator closing the tab, the execution ceiling) must not take the rotation with it,
    /// or the stored bundle keeps a dead token and the connection needs re-authorization. The detached
    /// round lands the rotation and releases the slot behind it; a refresh the provider refuses writes
    /// nothing and releases the slot the same way. A caller dropped while still waiting for the slot has
    /// nothing in flight, so that wait needs no such protection. A rotation the store refuses to write is
    /// not dropped either: see [`PendingRotation`].
    ///
    /// This reads and writes through the [`Store`] rather than the [`SecretBackend`], which is correct
    /// because the OAuth connect flow seals it there too: an externally-backed secret (Infisical, KMS)
    /// is never an OAuth bundle, so the two paths cannot diverge.
    async fn fresh_oauth_credential(
        &self,
        secret_id: &str,
        opened: crate::oauth_credential::OAuthCredential,
    ) -> Result<crate::oauth_credential::OAuthCredential, GatewayError> {
        let parked = self.oauth_pending_rotations.lock().unwrap_or_else(|p| p.into_inner()).contains_key(secret_id);
        if !parked && (!opened.needs_refresh(now_ms(), OAUTH_REFRESH_SKEW_MS) || !opened.is_locally_refreshable()) {
            return Ok(opened);
        }
        let held = self.oauth_refresh_slot(secret_id).lock_owned().await;
        let round = tokio::spawn(Self::refresh_oauth_credential(
            self.store.clone(),
            self.http.clone(),
            self.oauth_pending_rotations.clone(),
            secret_id.to_string(),
            held,
        ));
        // Dropping the handle detaches the round rather than aborting it, which is the point above.
        round.await.unwrap_or_else(|join| {
            Err(GatewayError::Internal(format!(
                "the refresh of secret '{secret_id}' did not finish: {join}"
            )))
        })
    }

    /// One refresh round under the slot it is handed: re-read the stored bundle, refresh it when it
    /// is still expired, and swap the result in only over the envelope it was read from. Two rounds at
    /// most: the second runs only when the secret was replaced under the first. Owns everything it
    /// touches so it can outlive the caller that spawned it; see [`Self::fresh_oauth_credential`].
    async fn refresh_oauth_credential(
        store: Arc<dyn Store>,
        http: Arc<dyn HttpClient>,
        pending: PendingRotations,
        secret_id: String,
        _held: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<crate::oauth_credential::OAuthCredential, GatewayError> {
        for _ in 0..2 {
            let Some(record) = store.get_secret(&secret_id)? else {
                pending.lock().unwrap_or_else(|p| p.into_inner()).remove(&secret_id);
                return Err(GatewayError::NotFound(format!("secret '{secret_id}'")));
            };
            let parked = pending.lock().unwrap_or_else(|p| p.into_inner()).get(&secret_id).cloned();
            let (expected, current) = match parked {
                Some(parked) if parked.expected == record.sealed => {
                    match store.put_secret_if_unchanged(&secret_id, &parked.expected, parked.sealed.clone()) {
                        Ok(true) => {
                            pending.lock().unwrap_or_else(|p| p.into_inner()).remove(&secret_id);
                            tracing::info!(secret_id = %secret_id, "a rotated OAuth credential the store refused earlier is now written");
                            let refreshed = Self::open_oauth_sealed(&secret_id, &parked.sealed)?;
                            (parked.sealed, refreshed)
                        }
                        Ok(false) => continue,
                        Err(e) => {
                            tracing::warn!(secret_id = %secret_id, error = %e, "the store still refuses a rotated OAuth credential; using it from memory");
                            (parked.expected, Self::open_oauth_sealed(&secret_id, &parked.sealed)?)
                        }
                    }
                }
                Some(_) => {
                    // The stored bundle moved on (the parked rotation landed, or a new authorization replaced it), and the store wins.
                    pending.lock().unwrap_or_else(|p| p.into_inner()).remove(&secret_id);
                    (record.sealed.clone(), Self::open_oauth_sealed(&secret_id, &record.sealed)?)
                }
                None => (record.sealed.clone(), Self::open_oauth_sealed(&secret_id, &record.sealed)?),
            };
            permaura_core::secret::clear_stack();
            let (_, refreshed) =
                crate::oauth_credential::ensure_fresh(&current, http.as_ref(), now_ms(), OAUTH_REFRESH_SKEW_MS)
                    .await?;
            let Some(refreshed) = refreshed else {
                return Ok(current);
            };
            let json = crate::oauth_connect::to_sealed_json(&refreshed)?;
            let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), json.as_bytes())
                .map_err(|e| GatewayError::Internal(format!("seal failed: {e}")))?;
            drop(json);
            permaura_core::secret::clear_stack();
            if Self::write_rotation(store.as_ref(), &pending, &secret_id, &expected, sealed).await {
                return Ok(refreshed);
            }
        }
        Err(GatewayError::Conflict(format!(
            "secret '{secret_id}' was replaced while its token was being refreshed"
        )))
    }

    fn open_oauth_sealed(
        secret_id: &str,
        sealed: &SealedSecret,
    ) -> Result<crate::oauth_credential::OAuthCredential, GatewayError> {
        let plain = permaura_core::open(sealed, vault_passphrase())
            .map_err(|e| GatewayError::Internal(format!("open failed: {e}")))?;
        crate::oauth_connect::from_sealed_bytes(&plain)
            .ok_or_else(|| GatewayError::Conflict(format!("secret '{secret_id}' is no longer an OAuth credential")))
    }

    /// Write a rotation the provider has already committed to. `false` means the secret was replaced
    /// over `expected` and the rotation is discarded. A store that refuses the write never loses it:
    /// the write is retried, and if the store still refuses, the rotation is kept as a
    /// [`PendingRotation`] and the call goes ahead with it.
    async fn write_rotation(
        store: &dyn Store,
        pending: &PendingRotations,
        secret_id: &str,
        expected: &SealedSecret,
        sealed: SealedSecret,
    ) -> bool {
        let mut retries = ROTATION_WRITE_RETRIES.iter();
        let refusal = loop {
            match store.put_secret_if_unchanged(secret_id, expected, sealed.clone()) {
                Ok(true) => {
                    pending.lock().unwrap_or_else(|p| p.into_inner()).remove(secret_id);
                    return true;
                }
                // An earlier attempt that reported a failure may have committed locally (a hosted store whose upload failed).
                Ok(false) => return Self::stored_is(store, secret_id, &sealed),
                // Committed here and not carried to the bucket: a retry would only upload the snapshot again under the store's lock.
                Err(e) if Self::stored_is(store, secret_id, &sealed) => break e,
                Err(e) => match retries.next() {
                    Some(wait) => tokio::time::sleep(*wait).await,
                    None => break e,
                },
            }
        };
        if Self::stored_is(store, secret_id, &sealed) {
            pending.lock().unwrap_or_else(|p| p.into_inner()).remove(secret_id);
            tracing::warn!(
                secret_id = %secret_id,
                error = %refusal,
                "a rotated OAuth credential is committed on this instance but not yet carried to the bucket; the next upload that succeeds carries it, and if this instance stops first the connection must be authorized again"
            );
            return true;
        }
        pending.lock().unwrap_or_else(|p| p.into_inner()).insert(
            secret_id.to_string(),
            PendingRotation { expected: expected.clone(), sealed },
        );
        tracing::error!(
            secret_id = %secret_id,
            error = %refusal,
            "the store refused a rotated OAuth credential the provider has already issued; it is kept in memory and written by the next refresh round, and if this process stops first the connection must be authorized again"
        );
        true
    }

    fn stored_is(store: &dyn Store, secret_id: &str, sealed: &SealedSecret) -> bool {
        matches!(store.get_secret(secret_id), Ok(Some(row)) if row.sealed == *sealed)
    }

    /// Drop every parked rotation whose secret is gone, so a deleted credential's envelope does not stay in memory for the life of the process.
    pub fn forget_rotations_of_deleted_secrets(&self) {
        let mut pending = self.oauth_pending_rotations.lock().unwrap_or_else(|p| p.into_inner());
        pending.retain(|secret_id, _| !matches!(self.store.get_secret(secret_id), Ok(None)));
    }

    /// The secret ids with a rotation parked in memory.
    pub fn parked_oauth_rotations(&self) -> Vec<String> {
        let mut ids: Vec<String> =
            self.oauth_pending_rotations.lock().unwrap_or_else(|p| p.into_inner()).keys().cloned().collect();
        ids.sort();
        ids
    }

    /// The refresh slot for one secret, created on demand. Slots nobody holds or waits on are dropped
    /// on the way, so the map stays the size of the credentials refreshing right now.
    fn oauth_refresh_slot(&self, secret_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut slots = self.oauth_refresh_slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.retain(|_, slot| Arc::strong_count(slot) > 1);
        slots.entry(secret_id.to_string()).or_default().clone()
    }

    /// Acquire a secret for one call, run `f` with it, and release the lease afterwards, on the
    /// success path and on every error path alike.
    ///
    /// For a stored secret there is no lease and this is exactly the old `resolve`. For a dynamic
    /// backend it is the whole point: the minted credential is handed back the moment the call
    /// finishes, so its live window is the call rather than its TTL. Release is best-effort and
    /// never turns a completed call into a failure; the TTL is what guarantees the credential
    /// eventually dies, including if this process is killed mid-call.
    ///
    /// A [`LeaseGuard`] covers the paths an `await` cannot: the request future being dropped
    /// (client disconnect, server timeout) or unwinding on a panic.
    async fn with_secret<T, F, Fut>(&self, secret_id: &str, f: F) -> Result<T, GatewayError>
    where
        F: FnOnce(OpenedSecret) -> Fut,
        Fut: std::future::Future<Output = Result<T, GatewayError>>,
    {
        let (opened, lease) = self.backend.acquire(secret_id).await?.into_parts();
        let guard = LeaseGuard { backend: self.backend.clone(), lease };
        let outcome = f(opened).await;
        guard.release().await;
        outcome
    }

    /// Send one gateway-initiated request that needs a connection's sealed credential, for a read the
    /// operator triggers and no agent can reach: listing a WordPress site's Abilities during a re-sync.
    ///
    /// The secret is opened exactly as invoke opens it ([`Self::with_secret`], then the same OAuth
    /// branch as [`Self::execute_http_with`]) and the plaintext only ever shapes the request. The gates
    /// invoke applies before touching a secret apply here too: the execution hold and restored
    /// authority nobody has confirmed. The custody gate is not one of them: like every MCP invoke the
    /// request executes on this gateway (`ExecutionLocation::LocalOnly`), whichever network the
    /// operator's request arrived over. The response is returned unredacted because it goes to the
    /// importer, never to an agent.
    pub async fn send_with_credential(
        &self,
        cap: &Capability,
        params: &serde_json::Value,
    ) -> Result<connectors::HttpResponse, GatewayError> {
        self.refuse_if_held()?;
        let review = self.reconciliation()?;
        for (kind, id) in [
            (crate::reconcile::ReviewKind::Connection, cap.resource.as_str()),
            (crate::reconcile::ReviewKind::Secret, cap.secret_id.as_str()),
        ] {
            if let Some(reason) = Self::refuse_if_unreviewed(review.as_ref(), kind, id) {
                return Err(GatewayError::Denied(reason));
            }
        }
        // The connection's family, never its id: a WordPress connection may be named after one.
        let connector = self.store.get_connection(&cap.resource)?.map(|c| c.connector).unwrap_or_else(|| cap.connector_id().to_string());
        let connector = connector.as_str();
        self.with_secret(&cap.secret_id, |opened| async move {
            let request = match crate::oauth_connect::from_sealed_bytes(opened.bytes()) {
                Some(cred) => {
                    drop(opened);
                    permaura_core::secret::clear_stack();
                    let cred = self.fresh_oauth_credential(&cap.secret_id, cred).await?;
                    connectors::build_request_for(connector, cap, params, cred.access_token.as_bytes())
                }
                None => {
                    let request = connectors::build_request_for(connector, cap, params, opened.bytes());
                    drop(opened);
                    request
                }
            }
            .map_err(|refusal| GatewayError::BadRequest(refusal.reason))?;
            permaura_core::secret::clear_stack();
            self.http
                .send(request)
                .await
                .map_err(|e| GatewayError::upstream("upstream call failed", &e))
        })
        .await
    }

    /// The HTTP path, with the secret already opened: shape an [`connectors::HttpRequest`], send it
    /// through the HTTP client the service was built with, and scrub and redact what comes back.
    #[allow(clippy::too_many_arguments)]
    async fn execute_http_with(
        &self,
        connector: &str,
        cap: &Capability,
        params: &serde_json::Value,
        opened: OpenedSecret,
        scrub: &mut CredentialScrub,
        redact_keys: &[String],
        trace: &ExecutionTrace,
    ) -> Result<Executed, GatewayError> {
        // The opened handle is dropped (and its bytes zeroized) before we touch the
        // network; from there the secret lives only inside the request's Authorization
        // header, exactly as before.
        //
        // The credential slot holds either raw secret bytes (an API key) or a sealed OAuth bundle.
        // For OAuth, refresh first if the access token is at or near expiry, and persist the result:
        // providers like Xero rotate the refresh token on every use, so a refresh whose write is
        // skipped locks the connection out permanently.
        let request = match crate::oauth_connect::from_sealed_bytes(opened.bytes()) {
            Some(cred) => {
                drop(opened);
                // Best effort, before the refresh's future is made: see clear_stack.
                permaura_core::secret::clear_stack();
                let cred = self.fresh_oauth_credential(&cap.secret_id, cred).await?;
                // A refresh mints credentials the sealed bundle the scrub was built from never held.
                scrub.add_secret(cred.access_token.as_bytes());
                if let Some(refresh) = &cred.refresh_token {
                    scrub.add_secret(refresh.as_bytes());
                }
                connectors::build_request_for(connector, cap, params, cred.access_token.as_bytes())
            }
            None => {
                let request = connectors::build_request_for(connector, cap, params, opened.bytes());
                drop(opened);
                request
            }
        }
        // The gate refused this input before policy; reaching here means a path that skipped it.
        .map_err(|refusal| GatewayError::Denied(refusal.reason))?;
        permaura_core::secret::clear_stack();

        // From here the upstream effect may have happened whatever comes back, so the terminal
        // event can no longer claim the call did not land. See [`ExecutionTrace`].
        trace.dispatched();
        let response = self
            .http
            .send_raw(request)
            .await
            .map_err(|e| GatewayError::upstream("upstream call failed", &e))?;

        // Scrub and redact the response with the call's effective set before it can reach the agent.
        // The body stays bytes: the agent's view is a streaming pass over them.
        let failed = !response.is_success();
        let (body, readable) = match self.projected(connector, cap, response.body).await? {
            Ok(body) => (body, true),
            Err(unread) => (unread, false),
        };
        // After the projection, which may wait for room in the pool, so nothing the aliases take is held while it does.
        let redaction = readable.then(|| connectors::response_redact_keys(connector, cap, params, redact_keys, self.memory.pool()));
        let viewed = match &redaction {
            None => Err(crate::memory::ViewRefusal::NotJson),
            Some(connectors::ResponseRedaction::Keys { keys, .. }) => self.memory.agent_view(&body, scrub, keys).await,
            Some(connectors::ResponseRedaction::Whole) => {
                tracing::warn!(
                    capability = %cap.id,
                    "the whole response was redacted: the call's GraphQL documents name more than {} distinct aliases of redacted fields, or the memory pool had no room for the aliases",
                    connectors::MAX_RESPONSE_ALIASES
                );
                Ok((JsonText::from_value(&serde_json::Value::String(permaura_core::REDACTED.to_string())), MemoryCharge::none()))
            }
        };
        let (redacted, diagnostic, room) = match viewed {
            // A JSON body's words reach the operator only from this redacted view: its raw text still holds every member redaction removed.
            Ok((redacted, room)) => {
                let diagnostic = if failed { upstream_error_message(&redacted) } else { None };
                (redacted, diagnostic, room)
            }
            // Empty, not JSON, or a body the projection could not read: the agent gets `null`, as it always has, and a failure's text is kept for the operator.
            Err(crate::memory::ViewRefusal::NotJson) => {
                (JsonText::null(), if failed { connectors::non_json_text(&body) } else { None }, MemoryCharge::none())
            }
            Err(refusal) => {
                return Err(GatewayError::Internal(format!("the call to '{}' was sent, but its answer could not be prepared: {refusal}", cap.id)))
            }
        };
        drop(body);
        Ok(Executed { status: response.status, redacted, headers: response.headers, diagnostic, room })
    }

    /// `body` narrowed to what `cap` promises ([`connectors::project_response`]) where the projection applies.
    /// It is structural, so for those capabilities the body is built into a tree, charged to the memory budget; the call has been sent by then, so a budget with no room is an error that says so, and never the raw body.
    /// That charge waits for room in the pool while the execution holds its params' room, or an approved call its held params' room and, unless it runs under an execution slot, a slot's share of byte buffers, so it can queue behind a larger reservation that needs what the call holds and stall both for the pool wait, as it could in gateway 1.3.52.
    /// A body the projection cannot read comes back as `Err`, for the diagnostic of a failed call only: the agent gets nothing of it, as of a body that is not JSON.
    async fn projected(&self, connector: &str, cap: &Capability, body: Vec<u8>) -> Result<Result<Vec<u8>, Vec<u8>>, GatewayError> {
        if !connectors::response_needs_projection(connector, cap) {
            return Ok(Ok(body));
        }
        let (tree, _charge) = match connectors::json_budget::parse_charged(self.memory.pool(), &body, 2, self.memory.wait()).await {
            Ok(parsed) => parsed,
            // Not handed to the streaming view: it skips a redacted member unread at any depth, so it accepts some of what this refuses, and the projection never ran on that.
            Err(connectors::json_budget::ChargedParseError::Json(_)) => return Ok(Err(body)),
            Err(refusal) => {
                return Err(GatewayError::Internal(format!(
                    "the call to '{}' was sent, but its response could not be read: {refusal}",
                    cap.id
                )))
            }
        };
        drop(body);
        let projected = connectors::project_response(connector, cap, tree);
        serde_json::to_vec(&projected).map(Ok).map_err(|e| GatewayError::Internal(format!("a projected response could not be written: {e}")))
    }

    /// The command path, with the secret already opened: build a [`connectors::CommandInvocation`]
    /// (injecting the opened secret as the command's env value), then run it via the command runner
    /// the service was built with. The result mirrors the HTTP shape: a
    /// `{ exit_code, output }` object where `output` is the scrubbed and redacted stdout, so the agent
    /// never sees the token or any sensitive stdout field. The command status maps to a synthetic
    /// HTTP code (200 on exit 0, 502 otherwise) so REST/MCP stay uniform.
    async fn execute_command_with(
        &self,
        spec: connectors::CommandSpec,
        params: &serde_json::Value,
        opened: OpenedSecret,
        scrub: &CredentialScrub,
        redact_keys: &[String],
        trace: &ExecutionTrace,
    ) -> Result<Executed, GatewayError> {
        // Build the invocation (injecting the opened secret as the env value), then drop the
        // handle (zeroizing the plaintext) before the child is ever spawned. A bad-input error
        // here (e.g. a metacharacter-laden param) surfaces as a 400-class gateway error.
        let invocation = connectors::build_command(&spec, params, opened.bytes())
            .map_err(|e| GatewayError::BadRequest(format!("command rejected: {e}")))?;
        drop(opened);
        permaura_core::secret::clear_stack();

        // The child may write, spend or send something the moment it is spawned, so from here the
        // terminal event can no longer claim nothing happened. See [`ExecutionTrace`].
        trace.dispatched();
        let output = self
            .command
            .run(invocation)
            .await
            .map_err(|e| GatewayError::Internal(format!("command run failed: {e}")))?;

        // Scrub and redact stdout (it may be JSON) with the call's effective set before it reaches the agent, as a stream, so no output its cap admits is refused for its shape.
        // stderr is summarized to a length only, never echoed, so a CLI that prints a token to stderr cannot leak it through the result.
        let redacted_stdout = permaura_core::json_stream::agent_view_of_output(&output.stdout, scrub, redact_keys);
        let status = if output.code == 0 { 200 } else { 502 };
        let diagnostic = (output.code != 0).then(|| exit_message(output.code, &redacted_stdout));
        let result = exit_result(output.code, &redacted_stdout, output.stderr.len());
        Ok(Executed { status, redacted: result, headers: Vec::new(), diagnostic, room: MemoryCharge::none() })
    }

    /// The SSH path, with the credential already opened: build the resolved
    /// [`connectors::SshInvocation`] (command allow-listing and path-scoping happen in `build_ssh`),
    /// drop the handle (zeroizing the plaintext) before the SSH runner dials, then run it via the SSH
    /// runner the service was built with. Results follow the same redaction contract as the command
    /// path: an exec's stdout is scrubbed and redacted and stderr is length-only; SFTP results are
    /// structured and file content is returned base64 (binary, so key-name redaction does not apply;
    /// [`scrubbed`] still removes the credential's base64 from it, and the per-call transfer cap is the
    /// exfil bound). Success maps to 200, a nonzero exit to 502.
    async fn execute_ssh_with(
        &self,
        spec: connectors::SshSpec,
        params: &serde_json::Value,
        opened: OpenedSecret,
        scrub: &CredentialScrub,
        redact_keys: &[String],
        trace: &ExecutionTrace,
    ) -> Result<Executed, GatewayError> {
        let mut invocation = connectors::build_ssh(&spec, params, opened.bytes())
            .map_err(|e| GatewayError::BadRequest(format!("ssh rejected: {e}")))?;
        drop(opened);
        permaura_core::secret::clear_stack();
        invocation.egress = if self.hosted { connectors::SshEgress::PublicOnly } else { connectors::SshEgress::Unrestricted };

        // The session is dialled and the remote command or transfer starts here, so from here the
        // terminal event can no longer claim nothing happened. See [`ExecutionTrace`].
        trace.dispatched();
        let outcome = self
            .ssh
            .run(invocation)
            .await
            .map_err(|e| GatewayError::Internal(format!("ssh run failed: {e}")))?;

        let shaped = match outcome {
            SshOutcome::Exec(output) => {
                // Identical treatment to a local command: stdout may be JSON (redact it), and stderr
                // is reduced to a length so a command that prints a token to stderr can't leak it.
                let redacted_stdout = permaura_core::json_stream::agent_view_of_output(&output.stdout, scrub, redact_keys);
                let status = if output.code == 0 { 200 } else { 502 };
                let diagnostic = (output.code != 0).then(|| exit_message(output.code, &redacted_stdout));
                Executed {
                    status,
                    redacted: exit_result(output.code, &redacted_stdout, output.stderr.len()),
                    headers: Vec::new(),
                    diagnostic,
                    room: MemoryCharge::none(),
                }
            }
            SshOutcome::Get { bytes, content_base64 } => {
                #[derive(serde::Serialize)]
                struct Got<'a> {
                    bytes: u64,
                    content_base64: &'a str,
                }
                Executed {
                    status: 200,
                    redacted: JsonText::from_serialize(&Got { bytes, content_base64: &content_base64 }).unwrap_or_default(),
                    headers: Vec::new(),
                    diagnostic: None,
                    room: MemoryCharge::none(),
                }
            }
            SshOutcome::Put { bytes } => {
                Executed::ok(serde_json::json!({ "bytes": bytes, "written": true }))
            }
            SshOutcome::List { entries, truncated } => {
                let entries: Vec<serde_json::Value> = entries
                    .into_iter()
                    .map(|e| serde_json::json!({ "name": e.name, "size": e.size, "is_dir": e.is_dir }))
                    .collect();
                Executed::ok(serde_json::json!({ "entries": entries, "truncated": truncated }))
            }
        };
        Ok(shaped)
    }

    /// Append a hash-chained, signed audit event for this decision. Records summaries
    /// only, never raw request/response bodies or secrets.
    fn audit(
        &self,
        session: &Session,
        cap: &Capability,
        decision: &str,
        execution_location: ExecutionLocation,
        summary: serde_json::Value,
    ) -> Result<(), GatewayError> {
        self.store.append_audit(audit_payload(
            session,
            cap,
            decision,
            execution_location,
            summary,
        ))?;
        if decision == "deny" {
            self.audit_ceiling.record_denial(&session.id);
        }
        // A denial grows the chain as an execution does, so it kicks the archive too: a gateway that only ever refuses keeps its hot window under the ceiling.
        if let (Some(archive), Ok(_)) = (&self.audit_archive, tokio::runtime::Handle::try_current()) {
            if let Ok(events) = self.store.audit_len() {
                let pressure = self.audit_ceiling.band(events) != crate::audit_ceiling::Band::Normal;
                archive.kick(self.store.clone(), events, pressure);
            }
        }
        Ok(())
    }
}

/// Why a call on `connection` must not leave the gateway, or `None` when its target is allowed.
///
/// Applies whenever the request URL comes from the agent: the generic-HTTP family, and any capability
/// [`connectors::takes_agent_url`] says would be built from `params.url` (one with no pinned request
/// shape on a typed connection, for example from a bundle). The host is derived by
/// [`connectors::parse_url`], the parser the HTTP client dispatches with, so the host judged here is the
/// host the credential reaches. An empty allowlist fails closed.
fn egress_refusal(
    connection: &permaura_core::Connection,
    cap: &Capability,
    params: &serde_json::Value,
) -> Option<String> {
    if !connectors::is_generic_http_connector(&connection.connector)
        && !connectors::takes_agent_url(&connection.connector, cap)
    {
        return None;
    }
    if connection.allowed_hosts.is_empty() {
        return Some(format!(
            "Connection '{}' takes its request URL from the agent and has no host allowlist configured: denied (fail-closed).",
            connection.name
        ));
    }
    let url = params.get("url").and_then(|v| v.as_str()).unwrap_or_default();
    match connectors::parse_url(url) {
        Ok(parts) if !connectors::host_allowed(&parts.host, &connection.allowed_hosts) => Some(format!(
            "Host '{}' is not on the allowlist for connection '{}'.",
            parts.host, connection.name
        )),
        // The credential rides in this request, so plain http would put it on the wire in clear: https only, whatever the allowlist says.
        Ok(parts) if parts.scheme != "https" => Some(format!(
            "Request URL refused: a request that carries a credential is sent over https only, not '{}'.",
            parts.scheme
        )),
        Ok(_) => None,
        Err(e) => Some(format!("Request URL refused: {e}.")),
    }
}

/// Shape one audit payload from a caller, a capability and a decision.
///
/// Split out of [`EnforcementService::audit`] so the terminal-event guard, which outlives the
/// borrow of the service, builds byte-identical payloads rather than a second shape of its own.
fn audit_payload(
    session: &Session,
    cap: &Capability,
    decision: &str,
    execution_location: ExecutionLocation,
    mut summary: serde_json::Value,
) -> AuditPayload {
    // An agent's input reaches these summaries through the reasons the gates write (a URL the egress gate could not parse, a connection's name), and the chain keeps every event resident, so each string is cut here; the intent was cut to its own bound where it was taken.
    crate::audit_bound::cut_strings(&mut summary, &["intent"]);
    let mut payload = AuditPayload::new(cap.id.clone(), cap.resource.clone(), decision);
    payload.user_id = session.user_id.clone();
    payload.agent_id = Some(session.agent_id.clone());
    payload.device_id = session.device_id.clone();
    payload.session_id = Some(session.id.clone());
    payload.execution_location = Some(match execution_location {
        ExecutionLocation::LocalOnly => "local".to_string(),
        ExecutionLocation::RemoteAllowed => "remote".to_string(),
    });
    payload.summary = summary;
    payload
}

/// What [`EnforcementService::gate`] decided about a call, short of acting on it.
enum Gate {
    /// Refused before the engine was asked, or on the grant it chose: the verdict, and what the deny
    /// event records beside its reason.
    Refused { decision: Decision, detail: serde_json::Value },
    /// The engine's verdict, with the connection the call runs on and the budget it holds if it runs.
    Resolved {
        connection: permaura_core::Connection,
        resolution: permaura_policy::Resolution,
        reservation: Option<BudgetReservation>,
    },
}

/// The `resolution_reason` of a held call the gateway refused at approval time because the session
/// that made it had been revoked, had expired or was gone.
pub const DENIED_SESSION_ENDED: &str = "session_ended";

/// The `resolution_reason` of a held control-plane change retired because the devices that could confirm it
/// when it was asked for have been revoked since, and the same change was asked for again.
pub const DENIED_INDEPENDENCE_REVOKED: &str = "independence_revoked";

/// `resolution_reason` on a held change retired at its confirm because it would lower more than it did when it was held:
/// another change since then removed what masked part of its effect. It has to be asked for again.
pub const DENIED_EFFECT_WIDENED: &str = "effect_widened";

/// Whether `approval` waits on a signer more independent of its requester than any key `keyring` still
/// trusts, so the single signature it takes can never be given.
fn independence_revoked_since(keyring: &ApproverKeyring, approval: &PendingApproval) -> bool {
    approval.required_signatures.max(1) == 1
        && approval
            .requested_by
            .as_ref()
            .is_some_and(|r| keyring.most_independent(r) < r.required_independence)
}

const SESSION_GONE: &str = "its session no longer exists";

/// Why `session` no longer stands behind the calls it had held, or `None` while it does: the two
/// conditions [`EnforcementService::authenticate`] refuses its bearer for.
fn session_lapse(session: &Session, now: i64) -> Option<&'static str> {
    if session.revoked {
        return Some("its session was revoked");
    }
    // An OAuth agent's row is never presented and its expiry is never extended, because the client's
    // JWT is the credential; only the row's revocation, the owner's tombstone, speaks for that agent.
    if session.is_expired(now) && !session.id.starts_with("sess_oauth:") {
        return Some("its session expired");
    }
    None
}

/// What re-running the gates for a held call at approval time decided.
enum HeldRecheck {
    /// The call may no longer run.
    Denied {
        /// Why, for the audit event.
        why: String,
        /// What the settled row says about it, when the gateway has a reason clients name.
        resolution_reason: Option<&'static str>,
    },
    /// The call is still authorized, and this is the redaction set its result gets.
    Allowed {
        /// The effective redaction set from the approval-time resolution.
        redact_keys: Vec<String>,
        /// The grant budget this execution holds until its terminal event charges it.
        reservation: Option<BudgetReservation>,
        /// The grant the approval-time resolution authorized the call on, which reserves and is charged.
        grant_id: Option<String>,
        /// That grant's policy, as the resolution named it.
        policy_id: Option<String>,
    },
}

/// How far an execution got before it stopped, which is the only thing that separates an upstream
/// effect that certainly did not happen from one nobody can rule out.
///
/// Set at each of the three transports, immediately before the byte that could cause the effect.
/// It is deliberately one-way and never read for control flow: it decides only what the terminal
/// audit event is allowed to claim.
///
/// The default is "not dispatched", so a transport added later that forgets to call
/// [`Self::dispatched`] would under-claim. [`ExecutionOutcome::classify`] is the backstop for that:
/// it demands a gateway-authored, structurally pre-dispatch error as well before it will say an
/// effect did not happen, and every transport failure in this file is an
/// [`GatewayError::Internal`], which is not one.
#[derive(Debug, Default)]
struct ExecutionTrace {
    dispatched: AtomicBool,
}

impl ExecutionTrace {
    fn new() -> Self {
        ExecutionTrace::default()
    }

    /// Record that the request, the child process or the SSH session is on its way.
    fn dispatched(&self) {
        self.dispatched.store(true, Ordering::SeqCst);
    }

    fn was_dispatched(&self) -> bool {
        self.dispatched.load(Ordering::SeqCst)
    }
}

/// What the terminal audit event says about the upstream effect of an execution that did not
/// return a result.
///
/// The distinction is the whole point of the event. "Failed" is a claim about the world that is
/// false whenever a request was sent and its answer never arrived, and an operator reading a chain
/// needs to know which of the two they are looking at before they go and check an upstream ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionOutcome {
    /// Nothing left the gateway. The upstream effect certainly did not happen.
    Refused,
    /// A request, a child process or an SSH session was under way when this stopped. The effect may
    /// have happened; nothing here can tell.
    Unknown,
}

impl ExecutionOutcome {
    /// The label recorded in the event.
    fn as_str(self) -> &'static str {
        match self {
            ExecutionOutcome::Refused => "refused",
            ExecutionOutcome::Unknown => "unknown",
        }
    }

    /// Decide what an errored execution may claim.
    ///
    /// Two conditions, both required, before it may say the effect did not happen: the trace saw no
    /// transport reached, **and** the error is one this gateway authors before any transport runs. A
    /// bare `!dispatched` would be enough if every transport were guaranteed to mark itself, and
    /// that is exactly the kind of guarantee a connector added later quietly breaks.
    fn classify(trace: &ExecutionTrace, error: &GatewayError) -> Self {
        if trace.was_dispatched() {
            return ExecutionOutcome::Unknown;
        }
        match error {
            // Refused by the hosted-command gate, by a connector's own input validation, or by a
            // lookup that failed before anything was built. All are raised above the transport.
            GatewayError::Denied(_)
            | GatewayError::BadRequest(_)
            | GatewayError::NotFound(_)
            | GatewayError::ExecutionHeld { .. }
            | GatewayError::TooManyRequests { .. } => ExecutionOutcome::Refused,
            _ => ExecutionOutcome::Unknown,
        }
    }
}

/// The `error_kind` of the terminal event that closes an execution a stopped process never finished.
pub const INTERRUPTED_ERROR_KIND: &str = "interrupted";

/// What [`EnforcementService::settle_interrupted_approvals`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InterruptedSettlement {
    /// Approvals whose execution began and never ended: each gained a terminal event and is now
    /// unresolved.
    pub interrupted: Vec<String>,
    /// Approvals whose chain already recorded how they ended while the row still read pending.
    pub reconciled: Vec<String>,
    /// Interrupted executions too recent to settle yet, because another instance may still be
    /// running them.
    pub deferred: usize,
    /// The execution ids of `invoke` calls whose execution began and never ended: each gained a terminal event, charged to its grant.
    pub invokes: Vec<String>,
    /// How long until the soonest deferred one may be settled.
    pub retry_in: Option<std::time::Duration>,
}

/// The terminal audit event that must follow the pre-execution `"attempt"`, and the guard that
/// makes "must" true.
///
/// The recovery and archive designs both assume every `"attempt"` is
/// followed by exactly one terminal event. Before this existed that held only when
/// `execute_allowed` returned a result: an upstream failure, the execution ceiling or an oversize
/// response left the `"attempt"` standing alone, and an archive reader had no way to tell a hung
/// execution from one that was never recorded.
///
/// Armed at construction and disarmed by [`Self::record`]. The `Drop` path exists for the one case
/// `record` cannot reach, a panic inside the execution task, and it writes the same honest outcome
/// the error path would.
struct TerminalEvent {
    store: Arc<dyn Store>,
    session: Session,
    cap: Capability,
    execution_location: ExecutionLocation,
    intent: Option<String>,
    grant_id: Option<String>,
    policy_id: Option<String>,
    /// Set only on the [`EnforcementService::resolve_approval`] path, where the execution is a held
    /// call a human released and the chain has to say who released it and how.
    approval: Option<ApprovalContext>,
    /// On the `invoke` path, the id its `attempt` carries, so a later boot can tell which attempt an earlier process never closed.
    execution_id: Option<String>,
    trace: Arc<ExecutionTrace>,
    armed: bool,
}

/// Who released a held call, carried into every terminal event that path writes.
///
/// `method` is the one place the signed-versus-bearer distinction survives, so it belongs on the
/// failure event as much as on the success one: an operator reading a chain full of `unknown`
/// outcomes needs to know whether a device signature was behind each of them.
#[derive(Clone)]
struct ApprovalContext {
    id: String,
    method: String,
    approver: Option<String>,
    detail: ApproverDetail,
}

/// The approving device's name, and every co-signer's, as the device registry had them at the moment
/// of approval.
///
/// A snapshot rather than a lookup at read time, so a device renamed or revoked later does not
/// rewrite who an owner would have seen approving. Display only: a device names itself when it
/// enrols, and the approver id beside it is the fact the signature proves.
#[derive(Clone, Default)]
struct ApproverDetail {
    name: Option<String>,
    /// The member behind a bearer resolution, from the operator token's actor claim. Never an
    /// authorization input; see [`crate::store::SessionActor`].
    actor: Option<String>,
    signers: Vec<(String, Option<String>)>,
    /// How many distinct people the counted signatures speak for, when any device signed.
    people: Option<u8>,
}

impl ApproverDetail {
    fn insert_into(&self, summary: &mut serde_json::Value) {
        let Some(map) = summary.as_object_mut() else { return };
        if let Some(name) = &self.name {
            map.insert("approver_name".into(), name.clone().into());
        }
        if let Some(actor) = &self.actor {
            map.insert("approver_actor".into(), actor.clone().into());
        }
        if let Some(people) = self.people {
            map.insert("people_signed".into(), people.into());
        }
        if self.signers.len() > 1 {
            let signers: Vec<serde_json::Value> = self
                .signers
                .iter()
                .map(|(approver, name)| serde_json::json!({ "approver": approver, "approver_name": name }))
                .collect();
            map.insert("signers".into(), signers.into());
        }
    }
}

/// What [`EnforcementService::execute_allowed_inner`] knows about a capability before it opens the
/// secret, so a refusal never acquires one.
enum Prepared {
    Http(String),
    Command(connectors::CommandSpec),
    Ssh(connectors::SshSpec),
}

/// The scrub for one call: the secret's plaintext, or for a sealed OAuth bundle every token and client
/// secret in it (the bundle's JSON is never what reaches an upstream).
fn credential_scrub(secret: &[u8]) -> CredentialScrub {
    let mut scrub = CredentialScrub::new();
    match crate::oauth_connect::from_sealed_bytes(secret) {
        Some(cred) => {
            scrub.add_secret(cred.access_token.as_bytes());
            for held in [&cred.refresh_token, &cred.client_secret].into_iter().flatten() {
                scrub.add_secret(held.as_bytes());
            }
        }
        None => scrub.add_secret(secret),
    }
    scrub
}

/// A command's or SSH exec's result as the agent receives it: `{exit_code, output, stderr_len}`, with the already-redacted output written in verbatim.
fn exit_result(code: i32, output: &JsonText, stderr_len: usize) -> JsonText {
    #[derive(serde::Serialize)]
    struct Exited<'a> {
        exit_code: i32,
        output: &'a serde_json::value::RawValue,
        stderr_len: usize,
    }
    JsonText::from_serialize(&Exited { exit_code: code, output: output.as_raw(), stderr_len }).unwrap_or_default()
}

/// The last step of every agent execution: scrub the injected credential out of everything it hands
/// back, which the agent, the approval row, the signed summary and the diagnostics table are all built
/// from. The result is scrubbed again here so a shape built without [`agent_view`] (an SFTP transfer)
/// is covered; the header values and the diagnostic were capped before they got here, so a tail cut
/// inside the credential goes too.
fn scrubbed(outcome: Result<Executed, GatewayError>, scrub: &CredentialScrub) -> Result<Executed, GatewayError> {
    if scrub.is_empty() {
        return outcome;
    }
    let mut executed = match outcome {
        Ok(executed) => executed,
        Err(error) => return Err(scrubbed_error(error, scrub)),
    };
    if let Some(clean) = permaura_core::json_stream::rescrubbed(&executed.redacted, scrub) {
        executed.redacted = clean;
    }
    for (_, value) in &mut executed.headers {
        if let std::borrow::Cow::Owned(clean) = scrub.scrub_truncated(value) {
            *value = clean;
        }
    }
    if let Some(message) = &mut executed.diagnostic {
        if let std::borrow::Cow::Owned(clean) = scrub.scrub_truncated(message) {
            *message = clean;
        }
    }
    Ok(executed)
}

/// An execution error's text reaches the agent, the 500 log line and the diagnostics table.
fn scrubbed_error(error: GatewayError, scrub: &CredentialScrub) -> GatewayError {
    let clean = |message: String| scrub.scrub_str(&message).into_owned();
    match error {
        GatewayError::Unauthorized(m) => GatewayError::Unauthorized(clean(m)),
        GatewayError::StepUpRequired(m) => GatewayError::StepUpRequired(clean(m)),
        GatewayError::Denied(m) => GatewayError::Denied(clean(m)),
        GatewayError::NotFound(m) => GatewayError::NotFound(clean(m)),
        GatewayError::BadRequest(m) => GatewayError::BadRequest(clean(m)),
        GatewayError::Conflict(m) => GatewayError::Conflict(clean(m)),
        GatewayError::Internal(m) => GatewayError::Internal(clean(m)),
        GatewayError::StoreUnavailable(m) => GatewayError::StoreUnavailable(clean(m)),
        GatewayError::VerifierWarming(m) => GatewayError::VerifierWarming(clean(m)),
        GatewayError::UpstreamTimeout(m) => GatewayError::UpstreamTimeout(clean(m)),
        GatewayError::SchemaTooNew(m) => GatewayError::SchemaTooNew(clean(m)),
        GatewayError::StoreHeld(m) => GatewayError::StoreHeld(clean(m)),
        GatewayError::AuditKeyMissing(m) => GatewayError::AuditKeyMissing(clean(m)),
        GatewayError::TooLarge(m) => GatewayError::TooLarge(clean(m)),
        GatewayError::TooManyRequests { reason, message, retry_after_secs, scope } => {
            GatewayError::TooManyRequests { reason, message: clean(message), retry_after_secs, scope }
        }
        GatewayError::AllowanceExceeded { allowance, current, limit, message } => {
            GatewayError::AllowanceExceeded { allowance, current, limit, message: clean(message) }
        }
        GatewayError::ExecutionHeld { hold_id, state, reason } => {
            GatewayError::ExecutionHeld { hold_id, state, reason: clean(reason) }
        }
    }
}

/// What an execution that returned produced: the agent's answer, plus what the operator's record keeps
/// about it.
#[derive(Debug)]
struct Executed {
    status: u16,
    /// The agent's answer, as its text.
    redacted: JsonText,
    /// The upstream's allowlisted response headers, for the signed summary.
    headers: Vec<(String, String)>,
    /// Why a call that returned did not succeed, for the purgeable diagnostics table only.
    diagnostic: Option<String>,
    /// The room `redacted` takes in the view-growth budget past what the execution's slot holds, kept as long as `redacted` is: an approved held call's until its result is stored and the row read back to answer the approver, a REST or MCP invoke's until its response has been sent ([`InvokeOutcome::Allowed`]), and a relayed invoke's until its result has been framed.
    room: MemoryCharge,
}

impl Executed {
    fn ok(redacted: serde_json::Value) -> Self {
        Executed { status: 200, redacted: JsonText::from_value(&redacted), headers: Vec::new(), diagnostic: None, room: MemoryCharge::none() }
    }

    fn succeeded(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The keys every executed-call terminal event adds to its summary. Only structured header
    /// values reach the chain; see [`connectors::is_chain_safe_header`].
    fn insert_into(&self, summary: &mut serde_json::Value, explained: bool) {
        let Some(map) = summary.as_object_mut() else { return };
        map.insert("ok".into(), self.succeeded().into());
        let headers: serde_json::Map<String, serde_json::Value> = self
            .headers
            .iter()
            .filter(|(k, v)| connectors::is_chain_safe_header(k, v))
            .map(|(k, v)| (k.clone(), v.clone().into()))
            .collect();
        if !headers.is_empty() {
            map.insert("headers".into(), headers.into());
        }
        if explained {
            map.insert("diagnostic".into(), true.into());
        }
    }

    /// The purgeable explanation of a call that did not succeed: its message and the allowlisted
    /// headers whose values are free text. `None` for a success, whose request ids are not kept.
    fn explanation(&self) -> Option<crate::store::CallDiagnostic> {
        if self.succeeded() {
            return None;
        }
        let message = self.diagnostic.as_deref().and_then(diagnostic_text);
        let headers: std::collections::BTreeMap<String, String> = self
            .headers
            .iter()
            .filter(|(k, v)| !connectors::is_chain_safe_header(k, v))
            .cloned()
            .collect();
        if message.is_none() && headers.is_empty() {
            return None;
        }
        Some(crate::store::CallDiagnostic {
            audit_seq: 0,
            recorded_at: now_ms(),
            message: message.unwrap_or_else(|| "The response carried no error message.".into()),
            headers,
        })
    }
}

impl TerminalEvent {
    /// Append the terminal event for an execution that ended in an error, and disarm.
    ///
    /// The error's own text is **not** recorded in the chain. A `reqwest` error renders the URL it
    /// was for, and on the generic-HTTP connector that URL is agent-supplied and can carry a query
    /// token, so the chain would acquire caller data the `"attempt"` deliberately leaves out. The
    /// stable kind and the outcome are what the chain keeps; the message, with URL queries stripped,
    /// goes to the purgeable diagnostics table beside it.
    fn record_error(&mut self, error: &GatewayError) -> Result<(), GatewayError> {
        let outcome = ExecutionOutcome::classify(&self.trace, error);
        self.record_error_as(error, outcome)
    }

    /// Close an attempt the fence itself refused, before any execution began. Stated rather than
    /// classified: nothing ran, and the fence is the one place that knows it without a trace.
    fn record_refused_at_fence(&mut self, error: &GatewayError) -> Result<(), GatewayError> {
        self.record_error_as(error, ExecutionOutcome::Refused)
    }

    fn record_error_as(&mut self, error: &GatewayError, outcome: ExecutionOutcome) -> Result<(), GatewayError> {
        let explanation = diagnostic_text(&error.to_string()).map(|message| crate::store::CallDiagnostic {
            audit_seq: 0,
            recorded_at: now_ms(),
            message,
            headers: Default::default(),
        });
        let mut summary = self.summary(serde_json::json!({
            "ok": false,
            "outcome": outcome.as_str(),
            "error_kind": error_kind(error),
            "dispatched": self.trace.was_dispatched(),
            "intent": self.intent,
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
        }));
        if explanation.is_some() {
            summary["diagnostic"] = true.into();
        }
        self.append("error", summary, explanation)
    }

    /// Close the attempt of a held call whose session ended after the approval-time recheck and
    /// before anything was sent, with the `denied` event that recheck writes.
    fn record_session_ended(&mut self, why: &str) -> Result<(), GatewayError> {
        let summary = self.summary(serde_json::json!({
            "reason": format!("re-validation failed at approval time: {why}"),
            "human_decision": "approved",
        }));
        self.append("denied", summary, None)
    }

    /// The terminal event for a held call a human approved and that returned a result.
    ///
    /// Byte-identical to the `"approved"` event [`EnforcementService::resolve_approval`] appended
    /// before this type owned that path: the same decision, the same keys, the same values. What
    /// changed is that it is now written from the same place the failure event is, so "exactly one
    /// terminal event" is a property of one type rather than of two call sites agreeing.
    fn record_approved(&mut self, executed: &Executed) -> Result<(), GatewayError> {
        let mut summary = self.summary(serde_json::json!({
            "status": executed.status,
            "result_summary": permaura_core::json_stream::summary(&executed.redacted),
            // Charge the executed call against the grant the approval-time recheck authorized it on.
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
        }));
        let explanation = executed.explanation();
        executed.insert_into(&mut summary, explanation.is_some());
        self.append("approved", summary, explanation)
    }

    /// Add the `invoke` path's execution id to a terminal summary, pairing it with its `attempt`.
    fn name_execution(&self, summary: &mut serde_json::Value) {
        if let (Some(id), Some(map)) = (self.execution_id.as_ref(), summary.as_object_mut()) {
            map.insert("execution_id".into(), id.clone().into());
        }
    }

    /// Fold the approval's identity into a summary, when there is one. On the `invoke` path there
    /// is not, and the summary is passed through untouched so those events do not move.
    fn summary(&self, mut summary: serde_json::Value) -> serde_json::Value {
        let Some(approval) = self.approval.as_ref() else { return summary };
        if let Some(map) = summary.as_object_mut() {
            map.insert("approval_id".into(), approval.id.clone().into());
            map.insert("method".into(), approval.method.clone().into());
            map.insert(
                "approver".into(),
                approval
                    .approver
                    .clone()
                    .map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        approval.detail.insert_into(&mut summary);
        summary
    }

    /// Append the terminal event for an execution that returned a result, and disarm.
    fn record_allow(&mut self, executed: &Executed, notified: bool) -> Result<(), GatewayError> {
        let mut summary = serde_json::json!({
            "status": executed.status,
            "result_summary": permaura_core::json_stream::summary(&executed.redacted),
            "intent": self.intent,
            // The matched grant id is what `AuditUsage` charges budget against.
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
            "notified": notified,
        });
        let explanation = executed.explanation();
        executed.insert_into(&mut summary, explanation.is_some());
        self.append("allow", summary, explanation)
    }

    /// Append the terminal event, and its purgeable explanation when there is one, as one unit.
    fn append(
        &mut self,
        decision: &str,
        summary: serde_json::Value,
        explanation: Option<crate::store::CallDiagnostic>,
    ) -> Result<(), GatewayError> {
        // Disarm first: a store that refuses this append will refuse the identical one `Drop` would
        // make, and a second attempt would only turn one missing record into two log lines.
        self.armed = false;
        let mut summary = summary;
        self.name_execution(&mut summary);
        // The charge is read off the payload by the rule every audit scan applies (`store::charged_grant_of`), so the counter and the chain agree.
        let payload = audit_payload(&self.session, &self.cap, decision, self.execution_location, summary);
        let charge = crate::store::charge_of(&payload);
        self.store.append_audit_terminal(payload, charge, explanation)?;
        Ok(())
    }
}

impl Drop for TerminalEvent {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let outcome = if self.trace.was_dispatched() {
            ExecutionOutcome::Unknown
        } else {
            ExecutionOutcome::Refused
        };
        let mut summary = self.summary(serde_json::json!({
            "ok": false,
            "outcome": outcome.as_str(),
            "error_kind": "abandoned",
            "dispatched": self.trace.was_dispatched(),
            "intent": self.intent,
            "grant_id": self.grant_id,
            "policy_id": self.policy_id,
        }));
        self.name_execution(&mut summary);
        let payload =
            audit_payload(&self.session, &self.cap, "error", self.execution_location, summary);
        let charge = crate::store::charge_of(&payload);
        if let Err(e) = self.store.append_audit_terminal(payload, charge, None) {
            tracing::error!(
                capability = %self.cap.id,
                error = %e,
                "an execution ended without recording its terminal audit event"
            );
        }
    }
}

/// The stable label for a failed execution, recorded in place of the error's own text.
fn error_kind(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::UpstreamTimeout(_) => "timeout",
        GatewayError::Denied(_) => "denied",
        GatewayError::BadRequest(_) => "bad_request",
        GatewayError::Conflict(_) => "conflict",
        GatewayError::NotFound(_) => "not_found",
        GatewayError::StoreUnavailable(_) => "storage",
        GatewayError::Unauthorized(_) | GatewayError::StepUpRequired(_) => "unauthorized",
        GatewayError::VerifierWarming(_) => "verifier_warming",
        GatewayError::TooManyRequests { .. } => "throttled",
        GatewayError::AllowanceExceeded { .. } => "allowance",
        GatewayError::ExecutionHeld { .. } => "held",
        GatewayError::SchemaTooNew(_) => "schema",
        GatewayError::StoreHeld(_) => "store_held",
        GatewayError::AuditKeyMissing(_) => "audit_key_missing",
        GatewayError::TooLarge(_) => "too_large",
        GatewayError::Internal(_) => "internal",
    }
}

/// How long a held vault export stays collectable. Ten minutes covers finding the phone and confirming,
/// and the CLI and console resume the moment the device signs, so an approval still unredeemed past it
/// is one nobody is waiting for, which is the one an agent holding the bearer would come back to spend.
pub const EXPORT_APPROVAL_TTL_MS: i64 = 10 * 60 * 1000;

/// The sentence a held call is shown and signed with. For a capability with a pinned HTTP shape it
/// leads with what the gateway sends, the method and path template, in the gateway's own words, and
/// quotes the capability's description only as the connector's: that text comes from whoever wrote the
/// manifest, document or site the capability was derived from, and can call a `DELETE` a list.
pub fn held_call_sentence(cap: &crate::connectors::Capability) -> String {
    let Some(http) = cap.http.as_ref().filter(|_| cap.kind == crate::connectors::CapabilityKind::Http) else { return cap.description.clone() };
    let sent = format!("{} {}", http.method.as_str(), quoted_http_path(&http.path));
    let said = cap.description.trim();
    if said.is_empty() || said == sent {
        return format!("send {sent}");
    }
    // The connector's words can neither close the quote nor open a clause of their own, and are cut before they crowd out the method.
    let mut quoted: String = said.chars().map(|c| match c {
        '"' => '\'',
        '(' => '[',
        ')' => ']',
        c if c.is_control() => ' ',
        c => c,
    }).take(HELD_SENTENCE_WORDS_MAX).collect();
    if said.chars().count() > HELD_SENTENCE_WORDS_MAX {
        quoted.push('…');
    }
    format!("send {sent} (\"{quoted}\", in the connector's words)")
}

/// Quote a path without letting its text add clauses to the gateway's sentence.
pub(crate) fn quoted_http_path(path: &str) -> String {
    let text: String = path.chars().map(|c| match c {
        '"' => '\'', '(' => '[', ')' => ']', c if c.is_control() => ' ', c => c,
    }).collect();
    format!("\"{text}\"")
}

/// The most characters of a connector's own description a held call's sentence quotes.
const HELD_SENTENCE_WORDS_MAX: usize = 160;

/// The deadline a held control-plane change created at `created_at` is given: [`crate::store::CONTROL_PLANE_HOLD_TTL_MS`], or sooner should holds in general ever expire sooner.
fn control_plane_hold_expiry(created_at: i64) -> i64 {
    let day = created_at.saturating_add(crate::store::CONTROL_PLANE_HOLD_TTL_MS);
    crate::relay::hold_expiry(created_at).map_or(day, |at| at.min(day))
}

/// Mark a held change retired by its deadline.
fn mark_expired(row: &mut PendingApproval) {
    row.status = crate::store::APPROVAL_EXPIRED.into();
    row.resolution_reason = Some(crate::store::APPROVAL_EXPIRED.into());
}

/// The ids of held changes the expiry sweep has taken whose expiry it has yet to finish recording; see [`EnforcementService::retire_expired_holds`].
const HOLD_EXPIRY_RECORDS_OWED_META: &str = "hold_expiry_records_owed";

/// How often a serving gateway looks for held control-plane changes past their deadline.
const HOLD_EXPIRY_SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Retire held control-plane changes past their deadline, at once and then every [`HOLD_EXPIRY_SWEEP_EVERY`], for as long as the gateway serves. A confirmation arriving between sweeps is refused against the same deadline, so the sweep only tidies the queue and records the end.
pub fn spawn_hold_expiry_sweep(service: Arc<EnforcementService>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(HOLD_EXPIRY_SWEEP_EVERY);
        loop {
            tick.tick().await;
            if let Err(e) = service.retire_expired_holds(now_ms()) {
                tracing::warn!(error = %e, "could not retire held changes past their deadline; retrying at the next sweep");
            }
        }
    })
}

/// What an export approval stores in place of its resume secret: lowercase hex SHA-256.
pub fn export_resume_digest(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(secret.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// An **unguessable** id suffix for approvals / sessions / grants / secrets: 16 bytes from the OS
/// CSPRNG, hex-encoded. These ids back security-sensitive values (session bearer tokens, the
/// single-use `approval_id` an approval binds to), so they must NOT be predictable or derived from
/// the clock (a clock-derived id is guessable by an attacker who knows roughly when it was minted).
pub fn short_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The agent an OAuth access token speaks for.
///
/// Identity is the per-CLIENT party (`azp`), NOT the consenting operator (`sub`): the same operator may
/// authorise several distinct MCP clients (ChatGPT, Claude, Cursor), each a separate DCR registration
/// with its own `azp`. Keying on `sub` would collapse them into one agent record sharing one grant set;
/// keying on `azp` keeps them independently grantable and revocable. Falls back to `sub` only for a
/// (non-conformant) token that omits `azp`.
pub(crate) fn oauth_agent_id(claims: &crate::oauth::VerifiedClaims) -> String {
    format!("oauth:{}", claims.azp.as_deref().unwrap_or(&claims.sub))
}

/// Whether `bearer` is an enrolment code an older gateway minted, before codes carried 128 bits: `ENRL-` and fewer than eight groups of hex digits, with or without the console prefix. Its session keeps the expiry it had instead of sliding, so a 64-bit bearer, stored as an unsalted digest, ends at most one TTL after its last use before the upgrade and its agent enrols again.
pub(crate) fn is_short_enrolment_code(bearer: &str) -> bool {
    let code = bearer.strip_prefix(crate::CONSOLE_TOKEN_PREFIX).unwrap_or(bearer);
    let Some(rest) = code.strip_prefix("ENRL-") else { return false };
    let groups: Vec<&str> = rest.split('-').collect();
    groups.len() < 8 && groups.iter().all(|g| !g.is_empty() && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The stored session row of an OAuth agent: never presented, but where its revocation is recorded.
pub(crate) fn oauth_session_id(agent_id: &str) -> String {
    format!("sess_{agent_id}")
}

/// A revoked row standing for a removed OAuth agent, for a removal that found none to revoke.
///
/// The client still holds a valid JWT after its agent is deleted, and without a row saying it was
/// removed its next call would register it afresh as Approved under the Default grant.
pub(crate) fn oauth_tombstone(agent_id: &str) -> Session {
    let now = now_ms();
    Session {
        class: Default::default(),
        opened_by: None,
        id: oauth_session_id(agent_id),
        agent_id: agent_id.to_string(),
        user_id: None,
        device_id: None,
        token: format!("tok_{}", short_id()),
        role: SessionRole::Agent,
        created_at: now,
        revoked: true,
        expires_at: Some(now),
        last_used_at: None,
        actor: None,
    }
}

/// Current Unix time in milliseconds (0 on clock error). Used to timestamp approvals.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Hash binding an audited decision to its exact request payload. Delegates to the canonical
/// [`permaura_core::request_hash`] so the gateway, the relay worker, and the control plane all
/// compute byte-identical, key-order-independent values.
pub fn request_hash(capability: &str, params: &serde_json::Value) -> String {
    permaura_core::request_hash(capability, params)
}

/// [`request_hash`] of a held call's params, read from the row's text. Every row is written in canonical key order, so this builds no tree; text that is not (nothing this gateway writes) is parsed under its own estimate and hashed from the tree.
pub fn held_request_hash(capability: &str, params: &JsonText) -> String {
    if let Some(hash) = permaura_core::json_stream::request_hash_of_text(capability, params.get()) {
        return hash;
    }
    let bytes = params.get().as_bytes();
    let tree = connectors::json_budget::value_from_slice(bytes, connectors::json_budget::estimate(bytes)).unwrap_or_default();
    request_hash(capability, &tree)
}

/// Two-tier call counts: per-grant (across all its agents) and per-`(grant, agent)`, each
/// within the grant's current period window. A charged terminal event
/// ([`crate::store::charged_grant_of`]) is one call. They are read from the materialized grant-usage
/// counter, which is charged in the same transaction as the terminal append that spends it, so
/// budgets survive restarts and archive prunes; a restore or a widened period can put it out of step
/// with the chain, and `POST /v1/grants/rebuild-usage` rebuilds it.
///
/// **A tally, not a borrow of the chain.** This used to hold `store.audit_events(None)`, a clone of
/// the whole resident audit window, and hold it for the length of the execution. At the eight
/// concurrent executions [`crate::limits::DEFAULT_MAX_INFLIGHT`] allows, that made one event cost
/// about ten times its own size in resident memory and set the hot audit ceiling. The counting now
/// happens inside the store, under the lock it already holds, and what comes back is a handful of
/// integers. The filter, the periods and the totals are unchanged: `the_counting_store_and_an_audit_scan_agree_across_every_period_kind`
/// is the proof.
///
/// **And no longer a scan at all.** It reads the materialised counter, which is charged inside the
/// same transaction as the `allow`/`approved` append that spends it. An audit scan answers correctly
/// only while every event it ever charged is still in the hot store, and the archive's whole purpose
/// is that they are not: the first prune would have reset every `Period::Total` budget to zero used
/// and widened a grant the owner believes is exhausted.
struct AuditUsage {
    counts: crate::store::GrantUsageCounts,
    reserved: BudgetBook,
}

/// Grant budget held by executions in flight: past the policy engine, before the terminal event that
/// charges the store's counter.
///
/// The counter is charged in the same append as the terminal `allow`/`approved` event, which follows
/// the upstream call. Without this, N concurrent invokes against a grant with one call left each
/// measured the counter before any of them had finished, all were allowed, and all ran. A call reserves
/// under this book's lock in the same critical section that measures and resolves, and holds the
/// reservation until its terminal append has charged the counter, so a concurrent call sees it either
/// as a reservation or as a charge. In-process only: it bounds one instance, which is where every
/// request for a tenant lands while its store is fenced to a single writer.
#[derive(Debug, Default, Clone)]
pub(crate) struct BudgetBook {
    totals: std::collections::HashMap<String, u64>,
    per_agent: std::collections::HashMap<(String, String), u64>,
    /// Executions an earlier process began and never closed, keyed by [`open_execution_key`], each holding its grant and agent until the boot settlement has charged it.
    carried: std::collections::HashMap<String, (String, String)>,
}

impl BudgetBook {
    fn carry(&mut self, key: String, grant_id: &str, agent_id: &str) {
        if self.carried.contains_key(&key) {
            return;
        }
        let agent_id = &crate::audit_bound::agent_key(agent_id);
        *self.totals.entry(grant_id.to_string()).or_insert(0) += 1;
        *self.per_agent.entry((grant_id.to_string(), agent_id.to_string())).or_insert(0) += 1;
        self.carried.insert(key, (grant_id.to_string(), agent_id.to_string()));
    }

    fn release_carried(&mut self, key: &str) {
        if let Some((grant_id, agent_id)) = self.carried.remove(key) {
            self.release(&grant_id, &agent_id);
        }
    }

    fn reserve(&mut self, book: &Arc<std::sync::Mutex<BudgetBook>>, grant_id: &str, agent_id: &str) -> BudgetReservation {
        let agent_id = &crate::audit_bound::agent_key(agent_id);
        *self.totals.entry(grant_id.to_string()).or_insert(0) += 1;
        *self.per_agent.entry((grant_id.to_string(), agent_id.to_string())).or_insert(0) += 1;
        BudgetReservation { book: book.clone(), grant_id: grant_id.to_string(), agent_id: agent_id.to_string() }
    }

    fn release(&mut self, grant_id: &str, agent_id: &str) {
        if let Some(n) = self.totals.get_mut(grant_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.totals.remove(grant_id);
            }
        }
        let key = (grant_id.to_string(), crate::audit_bound::agent_key(agent_id).into_owned());
        if let Some(n) = self.per_agent.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_agent.remove(&key);
            }
        }
    }
}

/// The key an execution's `attempt` and its terminal event share: the `invoke` path's execution id, or a held call's approval id.
fn open_execution_key(payload: &AuditPayload) -> Option<String> {
    let field = |key: &str| payload.summary.get(key).and_then(|v| v.as_str());
    if let Some(id) = field("execution_id") {
        return Some(format!("execution:{id}"));
    }
    match payload.decision.as_str() {
        "attempt" | "approved" | "denied" | "error" => field("approval_id").map(|id| format!("approval:{id}")),
        _ => None,
    }
}

/// One execution's hold on its grant's budget, given back when dropped.
pub(crate) struct BudgetReservation {
    book: Arc<std::sync::Mutex<BudgetBook>>,
    grant_id: String,
    agent_id: String,
}

impl Drop for BudgetReservation {
    fn drop(&mut self) {
        crate::store::bridge::lock_donating(&self.book)
            .unwrap_or_else(|e| e.into_inner())
            .release(&self.grant_id, &self.agent_id);
    }
}

impl AuditUsage {
    /// Count every grant's budget in one pass, then let go of the store.
    ///
    /// Every grant in scope gets a window, because the policy engine picks which ones to ask about
    /// out of the same list and asking later would mean going back to the chain. A `Total`-period
    /// grant's window is every event ever recorded; a periodic grant's starts one window ago.
    fn measure(
        store: &dyn Store,
        grants: &[permaura_core::Grant],
        now_ms: i64,
    ) -> Result<Self, GatewayError> {
        let windows: Vec<crate::store::GrantWindow<'_>> = grants
            .iter()
            .map(|g| crate::store::GrantWindow {
                grant_id: g.grant_id.as_str(),
                since_ms: g
                    .period
                    .window_secs()
                    .map(|secs| now_ms - secs * 1000)
                    .unwrap_or(i64::MIN),
            })
            .collect();
        Ok(AuditUsage { counts: store.read_grant_usage(&windows)?, reserved: BudgetBook::default() })
    }

    /// Count the executions in flight as already charged.
    fn with_reserved(mut self, book: &BudgetBook) -> Self {
        self.reserved = book.clone();
        self
    }
}

impl permaura_policy::GrantUsage for AuditUsage {
    fn grant_total(&self, grant_id: &str) -> u64 {
        self.counts.total(grant_id) + self.reserved.totals.get(grant_id).copied().unwrap_or(0)
    }
    fn grant_agent(&self, grant_id: &str, agent_id: &str) -> u64 {
        self.counts.agent(grant_id, agent_id)
            + self
                .reserved
                .per_agent
                .get(&(grant_id.to_string(), crate::audit_bound::agent_key(agent_id).into_owned()))
                .copied()
                .unwrap_or(0)
    }
}

#[cfg(test)]
mod grant_usage_tests {
    use super::*;
    use permaura_core::{AuditEvent, AuditPayload, Grant, GrantAgent, GrantPeriod};

    /// The computation this slice replaced, kept verbatim so the equality below is a comparison
    /// against the shipped behaviour rather than against a restatement of the new one.
    ///
    /// It is the body of `AuditUsage::count` as it stood before this slice, over the cloned `Vec` the
    /// caller used to hold. Do not "tidy" it: its value is that it is the old code.
    fn scanned(
        grants: &[Grant],
        audit: &[AuditEvent],
        now_ms: i64,
        grant_id: &str,
        agent_id: Option<&str>,
    ) -> u64 {
        let window_ms = grants
            .iter()
            .find(|g| g.grant_id == grant_id)
            .map(|g| g.period)
            .and_then(|p| p.window_secs())
            .map(|secs| secs * 1000);
        let since = window_ms.map(|w| now_ms - w).unwrap_or(i64::MIN);
        audit
            .iter()
            .filter(|e| e.timestamp >= since)
            .filter(|e| crate::store::charged_grant(e) == Some(grant_id))
            .filter(|e| match agent_id {
                Some(a) => e.payload.agent_id.as_deref() == Some(a),
                None => true,
            })
            .count() as u64
    }

    fn grant(id: &str, period: GrantPeriod, agents: &[&str]) -> Grant {
        Grant {
            grant_id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            is_default: false,
            policy_ids: vec!["pol".into()],
            agents: permaura_core::GrantAgents::Agents(
                agents.iter().map(|a| GrantAgent::new(*a)).collect(),
            ),
            period,
            overall_limit: None,
            default_per_agent_limit: None,
            expires_at: None,
        }
    }

    fn event(seq: u64, timestamp: i64, decision: &str, grant_id: Option<&str>, agent: Option<&str>) -> AuditEvent {
        let mut payload = AuditPayload::new("conn.act", "conn", decision);
        payload.agent_id = agent.map(str::to_string);
        payload.summary = match grant_id {
            Some(id) => serde_json::json!({ "grant_id": id, "status": 200 }),
            None => serde_json::json!({ "status": 200 }),
        };
        AuditEvent {
            seq,
            timestamp,
            prev_hash: permaura_core::GENESIS_PREV_HASH.to_string(),
            payload,
            hash: String::new(),
            signature: String::new(),
        }
    }

    /// A history wide enough that a filter that got any one clause wrong would diverge: four
    /// period kinds, events inside and outside every window, decisions that must not count, a
    /// grant id nothing matches, and events with no agent at all.
    fn history(now: i64) -> (Vec<Grant>, Vec<AuditEvent>) {
        let day = 86_400_000i64;
        let grants = vec![
            grant("g_total", GrantPeriod::Total, &["a1", "a2"]),
            grant("g_day", GrantPeriod::Day, &["a1", "a2"]),
            grant("g_week", GrantPeriod::Week, &["a1"]),
            grant("g_month", GrantPeriod::Month, &["a2"]),
            grant("g_unused", GrantPeriod::Day, &["a1"]),
        ];
        let mut events = Vec::new();
        let mut push = |ts: i64, decision: &str, g: Option<&str>, agent: Option<&str>| {
            events.push(event(events.len() as u64, ts, decision, g, agent));
        };
        for (offset, agent) in [(400 * day, "a1"), (40 * day, "a2"), (3 * day, "a1"), (0, "a2")] {
            // One of each period at each age, so every window boundary is straddled by something.
            for g in ["g_total", "g_day", "g_week", "g_month"] {
                push(now - offset, "allow", Some(g), Some(agent));
                push(now - offset, "approved", Some(g), Some(agent));
                // Decisions that are not a charge, at the same instants.
                push(now - offset, "deny", Some(g), Some(agent));
                push(now - offset, "attempt", Some(g), Some(agent));
                push(now - offset, "error", Some(g), Some(agent));
                push(now - offset, "requires_approval", Some(g), Some(agent));
            }
            // An allow with no grant id, and one charged to a grant nothing lists.
            push(now - offset, "allow", None, Some(agent));
            push(now - offset, "allow", Some("g_deleted"), Some(agent));
        }
        // Charges with no agent on them: they count towards the grant and towards no agent.
        push(now, "allow", Some("g_total"), None);
        push(now - day, "allow", Some("g_day"), None);
        // Exactly on a window boundary, which is inclusive.
        push(now - day, "allow", Some("g_day"), Some("a1"));
        push(now - 7 * day, "allow", Some("g_week"), Some("a1"));
        (grants, events)
    }

    /// The load-bearing test for commit 1: the counting store and the audit scan it replaced agree
    /// on every grant, every agent and every period kind, over the same generated history.
    ///
    /// Only grants in the list are compared, because that is the only thing either computation can
    /// be asked about: the engine resolves candidates out of the same `Vec` the windows are built
    /// from. A grant id absent from the list would have scanned unbounded and now counts zero, and
    /// there is no path that can ask.
    #[test]
    fn the_counting_store_and_an_audit_scan_agree_across_every_period_kind() {
        let now = 1_758_376_682_117i64;
        let (grants, events) = history(now);
        let windows: Vec<crate::store::GrantWindow<'_>> = grants
            .iter()
            .map(|g| crate::store::GrantWindow {
                grant_id: g.grant_id.as_str(),
                since_ms: g.period.window_secs().map(|s| now - s * 1000).unwrap_or(i64::MIN),
            })
            .collect();
        let counted = crate::store::tally_grant_usage(&windows, events.iter());

        let mut charged = 0u64;
        for g in &grants {
            let expected = scanned(&grants, &events, now, &g.grant_id, None);
            assert_eq!(
                counted.total(&g.grant_id),
                expected,
                "grant total for {} ({:?})",
                g.grant_id,
                g.period
            );
            charged += expected;
            for agent in ["a1", "a2", "never-seen"] {
                assert_eq!(
                    counted.agent(&g.grant_id, agent),
                    scanned(&grants, &events, now, &g.grant_id, Some(agent)),
                    "per-agent count for {}/{agent}",
                    g.grant_id
                );
            }
        }
        assert!(charged > 0, "the generated history must actually charge something");
    }

    /// The same equality, taken through a real store rather than over a `Vec`, so the wiring is
    /// covered as well as the filter.
    ///
    /// The appends are **charged**, because `AuditUsage` now reads the materialised counter rather
    /// than scanning the chain, and the counter is charged by the append that spends it. The rule
    /// applied here is `TerminalEvent::append`'s verbatim: an `allow` or `approved` decision
    /// carrying a grant id, and nothing else. An uncharged append of a charging event is a call
    /// site that forgot, and this test is the one that would notice.
    #[test]
    fn a_store_counts_its_own_chain_the_way_a_scan_of_it_would() {
        use crate::store::memory::MemoryStore;
        let store = MemoryStore::new();
        let grants = vec![
            grant("g_total", GrantPeriod::Total, &["a1"]),
            grant("g_day", GrantPeriod::Day, &["a1", "a2"]),
        ];
        for (decision, g, agent) in [
            ("allow", Some("g_total"), Some("a1")),
            ("allow", Some("g_total"), Some("a2")),
            ("approved", Some("g_day"), Some("a1")),
            ("deny", Some("g_day"), Some("a1")),
            ("allow", None, Some("a1")),
        ] {
            let mut payload = AuditPayload::new("conn.act", "conn", decision);
            payload.agent_id = agent.map(str::to_string);
            if let Some(id) = g {
                payload.summary = serde_json::json!({ "grant_id": id });
            }
            let charge = match (decision, g) {
                ("allow" | "approved", Some(id)) => Some(crate::store::GrantCharge::new(id)),
                _ => None,
            };
            store.append_audit_charged(payload, charge).unwrap();
        }
        let now = now_ms();
        let events = store.audit_events(None).unwrap();
        let usage = AuditUsage::measure(&store, &grants, now).unwrap();
        for g in &grants {
            assert_eq!(
                permaura_policy::GrantUsage::grant_total(&usage, &g.grant_id),
                scanned(&grants, &events, now, &g.grant_id, None),
            );
            for agent in ["a1", "a2"] {
                assert_eq!(
                    permaura_policy::GrantUsage::grant_agent(&usage, &g.grant_id, agent),
                    scanned(&grants, &events, now, &g.grant_id, Some(agent)),
                );
            }
        }
    }

    #[test]
    fn a_long_agent_id_is_sealed_cut_and_still_charged_to_the_whole_id_it_asks_with() {
        use crate::store::memory::MemoryStore;
        let store = MemoryStore::new();
        let agent = format!("oauth:{}", "c".repeat(4 * crate::audit_bound::TEXT_MAX));
        let grants = vec![grant("g_day", GrantPeriod::Day, &[agent.as_str()])];
        let mut payload = AuditPayload::new("conn.act", "conn", "allow");
        payload.agent_id = Some(agent.clone());
        payload.summary = serde_json::json!({ "grant_id": "g_day" });
        let event = store.append_audit_charged(payload, Some(crate::store::GrantCharge::new("g_day"))).unwrap();
        assert!(event.payload.agent_id.as_deref().unwrap().len() < crate::audit_bound::TEXT_MAX);
        assert_eq!(store.audit_events(None).unwrap()[0].payload.agent_id, event.payload.agent_id);

        let book = Arc::new(std::sync::Mutex::new(BudgetBook::default()));
        let reservation = book.lock().unwrap().reserve(&book, "g_day", &agent);
        book.lock().unwrap().carry("exec_1".into(), "g_day", crate::store::charge_agent(&event.payload));
        let reserved = book.lock().unwrap().clone();
        let usage = AuditUsage::measure(&store, &grants, now_ms()).unwrap().with_reserved(&reserved);
        assert_eq!(permaura_policy::GrantUsage::grant_agent(&usage, "g_day", &agent), 3);
        drop(reservation);
        book.lock().unwrap().release_carried("exec_1");
        assert!(book.lock().unwrap().per_agent.is_empty());
    }
}

/// The longest device name an audit event snapshots. A device names itself at enrolment, and an
/// unbounded name would be copied into every event it approves, once per signer.
const APPROVER_NAME_MAX: usize = 64;

/// The longest diagnostic message stored.
const DIAGNOSTIC_MESSAGE_MAX: usize = 500;

/// Trim, scrub URLs in, and cap a message bound for the diagnostics table.
///
/// URLs are scrubbed because the known paths from caller data into an error string are errors that
/// render the URL they were for, and a generic-HTTP URL is agent-supplied and can carry a token in its
/// query, its fragment or its userinfo.
fn diagnostic_text(message: &str) -> Option<String> {
    let collapsed = connectors::scrub_urls(message);
    let capped: String = collapsed.chars().take(DIAGNOSTIC_MESSAGE_MAX).collect();
    (!capped.is_empty()).then_some(capped)
}

/// The upstream's own explanation of a non-2xx JSON answer: the body itself when it is a string, else the first string among the fields APIs conventionally put it in, read from the already-redacted body and never from its raw text.
fn upstream_error_message(redacted: &JsonText) -> Option<String> {
    const POINTERS: [&str; 8] = [
        "/error/message",
        "/message",
        "/error",
        "/error_description",
        "/detail",
        "/errors/0/message",
        "/errors/0/detail",
        "/title",
    ];
    if let Some(body) = permaura_core::json_stream::string_at(redacted, "").filter(|b| !b.trim().is_empty()) {
        return Some(body);
    }
    POINTERS
        .iter()
        .filter_map(|p| permaura_core::json_stream::string_at(redacted, p))
        .find(|m| !m.trim().is_empty())
}

/// The explanation for a command or SSH exec that exited non-zero: the code, and the first line of
/// its (already redacted) output when there is one. stderr is never used; see the command path.
fn exit_message(code: i32, output: &JsonText) -> String {
    let output = permaura_core::json_stream::string_at(output, "");
    let first_line = output.as_deref().and_then(|o| o.lines().map(str::trim).find(|l| !l.is_empty()));
    match first_line {
        Some(line) => format!("exited with code {code}: {line}"),
        None => format!("exited with code {code}"),
    }
}

/// What an agent refused for want of room in the hold queue is told to wait, in seconds: holds clear when a human resolves them, as the pending-count ceiling's do.
const HELD_PARAMS_RETRY_AFTER_SECS: u64 = 300;

/// Build a [`Principal`] from a session for policy/audit context.
pub fn principal_for(session: &Session) -> Principal {
    Principal {
        user: session.user_id.clone(),
        agent: Some(session.agent_id.clone()),
        device: session.device_id.clone(),
        org: None,
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn the_upstream_message_is_read_from_the_conventional_fields() {
        let text = |value: serde_json::Value| JsonText::from_value(&value);
        let body = text(serde_json::json!({ "error": { "message": "Invalid API key", "type": "auth" } }));
        assert_eq!(upstream_error_message(&body).as_deref(), Some("Invalid API key"));
        let body = text(serde_json::json!({ "errors": [{ "message": "Not Found" }] }));
        assert_eq!(upstream_error_message(&body).as_deref(), Some("Not Found"));
        let body = text(serde_json::json!({ "error": "invalid_grant", "error_description": "expired" }));
        assert_eq!(upstream_error_message(&body).as_deref(), Some("invalid_grant"));
        assert_eq!(upstream_error_message(&JsonText::null()), None);
        assert_eq!(upstream_error_message(&text(serde_json::json!({ "ok": false }))), None);
    }

    #[test]
    fn a_diagnostic_scrubs_urls_with_or_without_a_scheme() {
        let scrubbed = diagnostic_text("upstream URL could not be parsed: api.example.com/x?token=s3cret").unwrap();
        assert!(!scrubbed.contains("s3cret"), "{scrubbed}");
        let scrubbed = diagnostic_text("bad url https://user:pw@api.example/x#access_token=s3cret").unwrap();
        assert!(!scrubbed.contains("s3cret") && !scrubbed.contains("pw@"), "{scrubbed}");
        assert!(scrubbed.contains("https://api.example/x?"), "{scrubbed}");
        assert_eq!(diagnostic_text("see issue #12, what?").as_deref(), Some("see issue #12, what?"));
    }

    #[test]
    fn a_bare_string_body_is_summarized_by_length_and_kept_as_the_message() {
        let body = JsonText::from_value(&serde_json::json!("Invalid API key sk_live_123"));
        // A bare string body is upstream text that key-based redaction never touches, and the summary is signed permanently, so only its length is kept.
        assert_eq!(permaura_core::json_stream::summary(&body), serde_json::json!({ "chars": 27 }));
        assert_eq!(upstream_error_message(&body).as_deref(), Some("Invalid API key sk_live_123"));
    }

    #[test]
    fn a_diagnostic_drops_url_queries_and_is_capped() {
        let text = diagnostic_text("upstream call failed: error sending request for url (https://api.example/x?token=s3cret)");
        let text = text.unwrap();
        assert!(!text.contains("s3cret"), "{text}");
        assert!(text.contains("https://api.example/x?"), "{text}");
        assert_eq!(diagnostic_text(&"x".repeat(2_000)).unwrap().chars().count(), DIAGNOSTIC_MESSAGE_MAX);
        assert_eq!(diagnostic_text("   "), None);
        assert_eq!(diagnostic_text("what?  no  url"), Some("what? no url".into()));
    }

    /// Two-person approvals name the devices whose signatures the quorum counted: a device revoked
    /// after it signed gave nothing, so it is not named as having approved.
    #[tokio::test]
    async fn signers_are_the_signatures_the_quorum_counted() {
        use base64::Engine as _;
        let key = |n: u8| {
            base64::engine::general_purpose::STANDARD
                .encode(ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes())
        };
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        crate::seed::seed(store.as_ref()).unwrap();
        let svc = EnforcementService::new(store.clone(), Arc::new(crate::connectors::MockHttpClient::new()));
        for (id, n) in [("device:a", 1), ("device:b", 2), ("device:c", 3)] {
            assert!(svc.trust_approver_key_durable(id, &key(n)).unwrap());
        }
        svc.revoke_approver_key("device:a").unwrap();

        let session = store.get_session("sess_demo").unwrap().unwrap();
        let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
        let held = svc
            .invoke(&session, "github.pull_requests.create", &params, Some("synthetic"), ExecutionLocation::LocalOnly)
            .await
            .unwrap();
        let InvokeOutcome::RequiresApproval { approval, .. } = held else { panic!("a High-risk call holds") };
        let mut row = store.get_approval(&approval.id).unwrap().unwrap();
        row.signatures = [("device:a", 1), ("device:b", 2), ("device:c", 3)]
            .into_iter()
            .map(|(id, n)| crate::store::CollectedSignature {
                approver: id.to_string(),
                key_fp: key_fingerprint(&key(n)),
                decided_at: 0,
            })
            .collect();
        store.put_approval(row).unwrap();

        svc.resolve_approval(&approval.id, true, "device_signed", Some("device:c")).await.unwrap();
        let event = store.audit_events(None).unwrap().into_iter().find(|e| e.payload.decision == "approved").unwrap();
        let signers: Vec<&str> = event.payload.summary["signers"]
            .as_array()
            .expect("two signatures counted")
            .iter()
            .map(|s| s["approver"].as_str().unwrap())
            .collect();
        assert_eq!(signers, vec!["device:b", "device:c"]);
    }

    #[test]
    fn a_failed_command_names_its_exit_code_and_first_output_line() {
        let text = |value: serde_json::Value| JsonText::from_value(&value);
        assert_eq!(exit_message(2, &text(serde_json::json!("\nerror: not logged in\nmore"))), "exited with code 2: error: not logged in");
        assert_eq!(exit_message(1, &text(serde_json::json!({ "k": 1 }))), "exited with code 1");
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::connectors::MockHttpClient;
    use crate::store::memory::MemoryStore;

    fn svc() -> EnforcementService {
        EnforcementService::new(Arc::new(MemoryStore::new()), Arc::new(MockHttpClient::new()))
    }

    fn claims(azp: &str, name: &str) -> crate::oauth::VerifiedClaims {
        crate::oauth::VerifiedClaims {
            // Same consenting operator across all clients, the security-relevant case.
            sub: "operator-1".into(),
            azp: Some(azp.into()),
            name: Some(name.into()),
            // What the AS mints for an MCP client: never the operator scope, that is the whole separation.
            scope: Some("openid profile mcp offline_access".into()),
            actor: None,
        }
    }

    /// The console's operator session carries the member it said was acting, and nothing about who it
    /// IS changes: the id and agent id still come from the owner's `sub`.
    #[test]
    fn an_operator_session_carries_the_acting_member_without_becoming_them() {
        let actor = crate::store::SessionActor { sub: "user_priya".into(), name: Some("Priya".into()), role: None, vault_export: None };
        let mut c = claims("console", "Console");
        c.actor = Some(actor.clone());
        let session = svc().operator_session_from_jwt(&c);
        assert_eq!(session.actor, Some(actor));
        assert_eq!(session.agent_id, "operator:operator-1");
        assert_eq!(session.user_id.as_deref(), Some("operator-1"));
    }

    /// The cold-start race, at the seam it is decided. A worker whose JWKS has not landed answers
    /// every authenticated request as "warming" (a retryable 503) rather than "unauthorized" (a 401
    /// the web proxy relabels as an operator token to re-pair), because until the keys arrive it
    /// cannot tell a good bearer from a bad one and must not pretend the credential is at fault.
    #[test]
    fn a_cold_verifier_answers_warming_not_unauthorized() {
        use crate::oauth::{OAuthRs, RsConfig};

        let oauth = Arc::new(OAuthRs::new(RsConfig {
            public_url: "https://g-test.permaura.com".into(),
            mcp_resource: "https://g-test.permaura.com/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.com".into(),
            jwks_uri: "https://permaura.com/api/auth/jwks".into(),
            owner_sub: Some("operator-owner".into()),
        }));
        assert!(!oauth.verifier_ready(), "the fixture RS starts with an empty key cache");

        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let backend: Arc<dyn SecretBackend> =
            Arc::new(LocalVaultBackend::new(store.clone(), vault_passphrase().to_vec()));
        let svc = EnforcementService::from_components(
            store,
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            Some(oauth),
        );

        // A JWT-shaped bearer cannot be verified while the RS holds no keys, so authenticate must
        // warm rather than reject.
        let err = svc.authenticate("aaa.bbb.ccc").unwrap_err();
        assert!(
            matches!(err, GatewayError::VerifierWarming(_)),
            "a cold verifier must warm, not reject: {err:?}",
        );
    }

    /// The session an OAuth agent's first call opens is in the chain once, under the agent's own session, with who consented and never its bearer; a repeat call opens nothing.
    #[test]
    fn an_oauth_agents_first_session_is_recorded_once() {
        let s = svc();
        let first = s.session_from_jwt(claims("client-recorded", "Recorded")).unwrap();
        s.session_from_jwt(claims("client-recorded", "Recorded")).unwrap();
        let opened: Vec<_> = s
            .store
            .audit_events(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.payload.action == SESSION_OPEN_ACTION && e.payload.resource == first.id)
            .collect();
        assert_eq!(opened.len(), 1, "one record for the one session opened: {opened:?}");
        let event = &opened[0];
        assert_eq!(event.payload.session_id.as_deref(), Some(first.id.as_str()));
        assert_eq!(event.payload.agent_id.as_deref(), Some(first.agent_id.as_str()));
        assert_eq!(event.payload.summary["via"], "oauth");
        assert_eq!(event.payload.summary["consented_by"], "operator-1");
        assert_eq!(event.payload.summary["new_agent"], true);
        let stored = s.store.get_session(&first.id).unwrap().unwrap();
        assert!(!serde_json::to_string(&event).unwrap().contains(&stored.token), "the bearer is not recorded");
    }

    #[test]
    fn jwt_agents_are_keyed_on_azp_not_sub() {
        let s = svc();
        let a = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        let b = s.session_from_jwt(claims("client-cursor", "Cursor")).unwrap();
        // Two distinct MCP clients authorised by the SAME operator must be distinct agents, each
        // independently grantable/revocable, not collapsed onto the operator's user id.
        assert_ne!(a.agent_id, b.agent_id);
        assert_eq!(s.store.list_agents().unwrap().len(), 2);
        // Re-presenting the same client is idempotent (no new agent, stable session).
        let a2 = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        assert_eq!(a2.agent_id, a.agent_id);
        assert_eq!(a2.id, a.id);
        assert_eq!(s.store.list_agents().unwrap().len(), 2);
    }

    #[test]
    fn jwt_without_azp_falls_back_to_sub() {
        let s = svc();
        let c = crate::oauth::VerifiedClaims {
            sub: "operator-1".into(),
            azp: None,
            name: None,
            scope: Some("mcp".into()),
            actor: None,
        };
        let sess = s.session_from_jwt(c).unwrap();
        assert_eq!(sess.agent_id, "oauth:operator-1");
    }

    #[test]
    fn a_jwt_agents_session_token_is_not_guessable_from_its_public_client_id() {
        // `azp` is a PUBLIC OAuth client id. The derived session token must NOT be
        // `tok_oauth:<azp>`, or an attacker who knows the (public) client id could present it as a
        // bearer and, because authenticate() checks session_by_token BEFORE verifying a JWT,
        // authenticate as the agent with no valid token at all.
        let s = svc();
        let sess = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        assert_eq!(sess.agent_id, "oauth:client-claude");

        // The forgeable token must NOT be what authenticates.
        assert_ne!(sess.token, "tok_oauth:client-claude");
        assert!(
            s.authenticate("tok_oauth:client-claude").is_err(),
            "the deterministic, public-id-derived token must not authenticate",
        );

        // The random token that WAS minted is a valid session (sanity: we didn't just break auth).
        let got = s.authenticate(&sess.token).expect("the real random token authenticates");
        assert_eq!(got.agent_id, "oauth:client-claude");
        assert_eq!(got.role, SessionRole::Agent);
    }

    /// A row minted before the expiry cap has no `expires_at`, and the JWT path never touches it, so the
    /// idle sweep finds it 30 days after it was created however busy its client is. Retiring it as
    /// revoked made it indistinguishable from the owner revoking it, and the client was refused.
    #[test]
    fn a_legacy_oauth_row_the_idle_sweep_finds_does_not_lock_its_client_out() {
        let s = svc();
        let first = s.session_from_jwt(claims("client-legacy", "Legacy")).unwrap();
        let mut legacy = s.store.get_session(&first.id).unwrap().unwrap();
        legacy.expires_at = None;
        legacy.created_at = now_ms() - crate::store::AGENT_SESSION_TTL_MS - 60_000;
        s.store.put_session(legacy).unwrap();

        crate::sweep_idle_agent_sessions(s.store.as_ref(), false);
        assert!(
            !s.store.get_session(&first.id).unwrap().is_some_and(|row| row.revoked),
            "the sweep must not leave a revoked row that reads as the owner's decision"
        );

        let again = s.session_from_jwt(claims("client-legacy", "Legacy")).expect("the client still works");
        assert_eq!(again.agent_id, "oauth:client-legacy");
        let row = s.store.get_session(&again.id).unwrap().expect("a fresh row");
        assert!(!row.revoked && row.expires_at.is_some(), "re-created with an expiry, as on first contact");
        assert_eq!(s.store.get_agent("oauth:client-legacy").unwrap().unwrap().status, AgentStatus::Approved);
    }

    #[test]
    fn new_jwt_agent_is_approved_by_default() {
        // Default posture: AS consent == approval, so a freshly-seen OAuth agent can invoke at once.
        let s = svc();
        let sess = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        let agent = s.store.get_agent(&sess.agent_id).unwrap().unwrap();
        assert_eq!(agent.status, AgentStatus::Approved);
    }

    /// The AS can mint a gateway-audience token off an identity-only consent (no `resource` at authorize, one introduced at the token endpoint), and the user was told that sign-in "gets no access to your gateway". The scope is the one thing that records what was consented, so a token without `mcp` is refused with a 403 that names it, and no agent is registered.
    #[test]
    fn a_token_without_the_mcp_scope_is_refused_as_an_agent_and_registers_nothing() {
        let s = svc();
        for scope in [Some("openid profile offline_access"), Some("openid"), None] {
            let mut c = claims("client-sign-in", "Sign in with Permaura");
            c.scope = scope.map(String::from);
            let err = s.session_from_jwt(c).expect_err("an identity-only token is not an agent");
            match &err {
                GatewayError::Denied(why) => {
                    assert!(why.contains("`mcp` scope"), "the refusal names the scope: {why}");
                    match scope {
                        Some(scope) => assert!(why.contains(scope), "and what the token carried instead: {why}"),
                        None => assert!(why.contains("absent"), "{why}"),
                    }
                }
                other => panic!("expected a 403, got {other:?}"),
            }
            assert!(s.store.get_agent("oauth:client-sign-in").unwrap().is_none(), "no agent row for scope {scope:?}");
            assert!(s.store.get_session(&oauth_session_id("oauth:client-sign-in")).unwrap().is_none());
        }
    }

    /// The scope is matched as a token, so neither a look-alike nor a substring grants the agent plane.
    #[test]
    fn a_lookalike_mcp_scope_does_not_make_an_agent() {
        let s = svc();
        for scope in ["mcpx", "xmcp", "permaura:mcp", "openid mcp-readonly"] {
            let mut c = claims("client-lookalike", "Lookalike");
            c.scope = Some(scope.into());
            assert!(matches!(s.session_from_jwt(c), Err(GatewayError::Denied(_))), "{scope} must not act as an agent");
        }
        let mut c = claims("client-real", "Real");
        c.scope = Some("offline_access mcp openid".into());
        assert!(s.session_from_jwt(c).is_ok(), "the real scope among others does");
    }

    #[test]
    fn approval_gate_lands_new_jwt_agent_pending() {
        // With the gate on, a new agent lands Pending (invokes denied) until an operator approves,
        // and stays Pending across repeated JWT calls (the bug fix: no auto-approve on every call).
        let s = svc();
        s.set_require_agent_approval(true).unwrap();
        let sess = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        let agent = s.store.get_agent(&sess.agent_id).unwrap().unwrap();
        assert_eq!(agent.status, AgentStatus::Pending);

        // A second authenticated call must NOT silently promote it to Approved.
        s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        let still = s.store.get_agent(&sess.agent_id).unwrap().unwrap();
        assert_eq!(still.status, AgentStatus::Pending);
    }

    #[test]
    fn operator_approval_sticks_across_jwt_calls() {
        // Once an operator approves a gated agent, a later JWT call keeps it Approved (and a name
        // change still updates the record without resetting the status).
        let s = svc();
        s.set_require_agent_approval(true).unwrap();
        let sess = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        // Operator approves in the console.
        s.store
            .put_agent(Agent::approved(&sess.agent_id, "Claude", now_ms()))
            .unwrap();
        s.session_from_jwt(claims("client-claude", "Claude Desktop")).unwrap();
        let agent = s.store.get_agent(&sess.agent_id).unwrap().unwrap();
        assert_eq!(agent.status, AgentStatus::Approved);
        assert_eq!(agent.name, "Claude Desktop");
    }

    #[test]
    fn turning_the_gate_on_does_not_demote_existing_agents() {
        // Flipping the gate on affects only agents seen afterwards: an already-approved agent
        // keeps working; a brand-new one is gated.
        let s = svc();
        let existing = s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        s.set_require_agent_approval(true).unwrap();
        s.session_from_jwt(claims("client-claude", "Claude")).unwrap();
        assert_eq!(
            s.store.get_agent(&existing.agent_id).unwrap().unwrap().status,
            AgentStatus::Approved,
        );
        let fresh = s.session_from_jwt(claims("client-cursor", "Cursor")).unwrap();
        assert_eq!(
            s.store.get_agent(&fresh.agent_id).unwrap().unwrap().status,
            AgentStatus::Pending,
        );
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    use crate::backend::{Lease, LeasedSecret, SecretBackend};
    use crate::connectors::MockHttpClient;
    use crate::store::memory::MemoryStore;
    use std::sync::atomic::AtomicUsize;

    /// A backend that always mints a lease and counts how many it got back. The point of the
    /// dynamic path is that the credential's live window is one call, which only holds if the
    /// enforcement loop releases on EVERY exit, not just the happy one.
    struct CountingBackend {
        acquired: AtomicUsize,
        released: AtomicUsize,
    }

    impl CountingBackend {
        fn new() -> Arc<Self> {
            Arc::new(CountingBackend {
                acquired: AtomicUsize::new(0),
                released: AtomicUsize::new(0),
            })
        }
        fn counts(&self) -> (usize, usize) {
            (
                self.acquired.load(Ordering::SeqCst),
                self.released.load(Ordering::SeqCst),
            )
        }
    }

    #[async_trait::async_trait]
    impl SecretBackend for CountingBackend {
        async fn resolve(&self, _secret_id: &str) -> Result<OpenedSecret, GatewayError> {
            Err(GatewayError::Internal("dynamic: use acquire".into()))
        }
        async fn acquire(&self, secret_id: &str) -> Result<LeasedSecret, GatewayError> {
            self.acquired.fetch_add(1, Ordering::SeqCst);
            Ok(LeasedSecret::leased(
                OpenedSecret::new(b"minted_cred".to_vec()),
                Lease {
                    secret_id: secret_id.to_string(),
                    id: "lease_x".into(),
                    expires_at_ms: None,
                },
            ))
        }
        async fn release(&self, _lease: &Lease) {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
        fn holds_externally(&self, _secret_id: &str) -> Result<bool, GatewayError> {
            Ok(true)
        }
    }

    fn svc_with(backend: Arc<dyn SecretBackend>) -> EnforcementService {
        EnforcementService::from_components(
            Arc::new(MemoryStore::new()),
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            None,
        )
    }

    #[tokio::test]
    async fn a_lease_is_released_after_a_successful_call() {
        let counting = CountingBackend::new();
        let svc = svc_with(counting.clone());
        let out = svc
            .with_secret("sec_db", |opened| async move {
                assert_eq!(opened.bytes(), b"minted_cred");
                Ok::<_, GatewayError>(42)
            })
            .await
            .unwrap();
        assert_eq!(out, 42);
        assert_eq!(counting.counts(), (1, 1), "one mint, one release");
    }

    #[tokio::test]
    async fn a_lease_is_released_when_the_call_fails() {
        // The path that actually matters: an upstream error must not strand a live credential for
        // the rest of its TTL. Every `?` inside the execute_* bodies lands here.
        let counting = CountingBackend::new();
        let svc = svc_with(counting.clone());
        let err = svc
            .with_secret("sec_db", |_opened| async {
                Err::<(), _>(GatewayError::Internal("upstream exploded".into()))
            })
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Internal(_)));
        assert_eq!(counting.counts(), (1, 1), "a failed call still hands the lease back");
    }

    #[tokio::test]
    async fn a_cancelled_call_still_hands_the_lease_back() {
        // The case an `await` cannot cover: the request future is dropped part-way (a client
        // disconnect or a server timeout cancels the axum handler). Without the drop guard, the
        // requests that went wrong would be exactly the ones that strand a live credential.
        let counting = CountingBackend::new();
        let svc = svc_with(counting.clone());
        {
            let call = svc.with_secret("sec_db", |_opened| async {
                // Never completes; stands in for an upstream that hangs until the caller gives up.
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                Ok::<(), GatewayError>(())
            });
            tokio::pin!(call);
            let timed_out =
                tokio::time::timeout(std::time::Duration::from_millis(20), &mut call).await;
            assert!(timed_out.is_err(), "the call must still be in flight when we drop it");
        }
        // The guard's release is detached; give it a turn of the runtime.
        for _ in 0..8 {
            if counting.counts().1 > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(counting.counts(), (1, 1), "a cancelled call must not strand the credential");
    }

    #[tokio::test]
    async fn a_failed_acquire_releases_nothing() {
        struct FailingBackend;
        #[async_trait::async_trait]
        impl SecretBackend for FailingBackend {
            async fn resolve(&self, _: &str) -> Result<OpenedSecret, GatewayError> {
                Err(GatewayError::NotFound("secret".into()))
            }
            fn holds_externally(&self, _: &str) -> Result<bool, GatewayError> {
                Ok(false)
            }
        }
        let svc = svc_with(Arc::new(FailingBackend));
        let err = svc
            .with_secret("missing", |_| async { Ok::<(), GatewayError>(()) })
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::NotFound(_)));
    }

    #[tokio::test]
    async fn a_stored_secret_needs_no_release() {
        // The default trait impl: local/KMS/static-Infisical secrets keep exactly their old
        // behaviour: resolve, use, drop. Nothing to hand back.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let sealed = permaura_core::seal(Cipher::Aes256Gcm, b"pass", b"static_val").unwrap();
        store
            .put_secret(permaura_core::SecretRecord {
                id: "sec_static".into(),
                sealed,
                metadata: permaura_core::SecretMetadata::default(),
            })
            .unwrap();
        let backend: Arc<dyn SecretBackend> =
            Arc::new(crate::backend::LocalVaultBackend::new(store, b"pass".to_vec()));
        let (opened, lease) = backend.acquire("sec_static").await.unwrap().into_parts();
        assert_eq!(opened.bytes(), b"static_val");
        assert!(lease.is_none());
    }
}

#[cfg(test)]
mod keyring_persistence_tests {
    use super::*;
    use crate::connectors::MockHttpClient;
    use crate::manifest::InstalledManifest;
    use crate::store::memory::MemoryStore;
    use crate::store::{EnrolmentCode, SecretCustody};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use permaura_core::{AuditEvent, Connection, Grant, Policy, SecretRecord};

    fn pubkey(seed: u8) -> String {
        STANDARD.encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
    }

    /// A service whose trust state lives in `gateway_meta`: what a hosted (Mode C) worker gets.
    /// The field is set directly rather than through `PERMAURA_HOSTED` because the environment is
    /// process-global and these tests run alongside every other test in the crate.
    fn hosted(store: Arc<dyn Store>) -> EnforcementService {
        let mut svc = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
        svc.keyring_persistence = KeyringPersistence::Store;
        svc.hosted = true;
        svc.refresh_keyring_now();
        svc
    }

    /// A timeout is the case the distinction exists for. The request is with the upstream and the
    /// gateway stopped waiting; whether the effect happened is somebody else's ledger.
    #[test]
    fn a_timeout_after_the_request_went_out_can_never_claim_the_effect_did_not_happen() {
        let trace = ExecutionTrace::new();
        trace.dispatched();
        let err = GatewayError::UpstreamTimeout("ran past the ceiling".into());
        assert_eq!(ExecutionOutcome::classify(&trace, &err), ExecutionOutcome::Unknown);
        assert_eq!(error_kind(&err), "timeout");
    }

    /// The backstop for a transport added later that forgets to mark itself. An undispatched trace
    /// alone is not enough: the error has to be one this gateway raises above every transport.
    #[test]
    fn an_unmarked_transport_failure_still_reads_as_unknown() {
        let trace = ExecutionTrace::new();
        let unmarked = GatewayError::Internal("a new connector's transport failed".into());
        assert_eq!(
            ExecutionOutcome::classify(&trace, &unmarked),
            ExecutionOutcome::Unknown,
            "an internal failure is never evidence that nothing was sent"
        );
        let above = GatewayError::BadRequest("command rejected".into());
        assert_eq!(ExecutionOutcome::classify(&trace, &above), ExecutionOutcome::Refused);
    }

    /// A hosted container has nothing worth running, and the credential would land in a child
    /// process environment. No built-in preset produces a Command capability, so one reaches a hosted
    /// worker only through an imported bundle or an installed manifest, by which point it is stored:
    /// refusing at invoke is what makes an already-stored one inert.
    /// The worker knows it is hosted; a caller saying `local_only` cannot make it forget.
    #[tokio::test]
    async fn a_hosted_worker_treats_every_call_as_remote_for_a_local_only_secret() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        crate::seed::seed(store.as_ref()).unwrap();
        let session = store.get_session("sess_demo").unwrap().unwrap();
        let outcome = hosted(store)
            .invoke(
                &session,
                "braintree.transactions.search",
                &serde_json::json!({ "status": "failed" }),
                None,
                ExecutionLocation::LocalOnly,
            )
            .await
            .unwrap();
        match outcome {
            InvokeOutcome::Denied { decision } => assert!(decision.reason.contains("local-only"), "{}", decision.reason),
            _ => panic!("a hosted call against a local-only secret must be denied"),
        }
    }

    #[tokio::test]
    async fn a_hosted_worker_refuses_to_run_a_command_capability() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let cap = permaura_connectors::Capability {
            id: "vercel-cli.whoami".into(),
            description: "Print the Vercel account the token belongs to".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: "vercel_prod".into(),
            secret_id: "sec-vercel".into(),
            kind: permaura_connectors::CapabilityKind::Command,
            command: Some(permaura_connectors::CommandSpec {
                program: "vercel".into(),
                args_template: vec!["whoami".into()],
                secret_env: "VERCEL_TOKEN".into(),
                allowed_placeholders: vec![],
            }),
            http: None,
            ssh: None,
        };

        let trace = ExecutionTrace::new();
        let err = hosted(store.clone())
            .execute_allowed(&cap, &serde_json::json!({}), &permaura_core::default_redact_keys(), &trace)
            .await
            .expect_err("a hosted worker must not run a command capability");
        assert!(
            matches!(err, GatewayError::Denied(ref m) if m.contains("hosted gateway")),
            "the refusal must say why: {err:?}"
        );
        assert_eq!(
            ExecutionOutcome::classify(&trace, &err),
            ExecutionOutcome::Refused,
            "nothing was spawned, so the terminal event may say the effect did not happen"
        );

        // Unchanged off hosted: the mock runner answers rather than the guard.
        let svc = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
        assert!(
            !matches!(
                svc.execute_allowed(&cap, &serde_json::json!({}), &[], &ExecutionTrace::new()).await,
                Err(GatewayError::Denied(ref m)) if m.contains("hosted gateway")
            ),
            "a self-run gateway must not hit the hosted guard"
        );
    }

    /// An SSH capability stored before hosts were screened, or imported, still never
    /// points a hosted worker at the metadata server, its own loopback or the VPC. Refused before the
    /// credential opens and before the transport is asked to dial.
    #[tokio::test]
    async fn a_hosted_worker_refuses_to_dial_ssh_to_a_non_public_host() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        crate::seed::seed(store.as_ref()).unwrap();
        let seeded = store.get_capability("ssh.uptime").unwrap().expect("the seeded SSH capability");
        let aimed_at = |host: &str| {
            let mut cap = seeded.clone();
            cap.ssh.as_mut().unwrap().target.host = host.to_string();
            cap
        };
        for host in [
            "169.254.169.254", "metadata.google.internal", "127.0.0.1", "2130706433", "[::1]", "localhost", "10.0.0.1",
        ] {
            let runner = Arc::new(MockSshRunner::new());
            let trace = ExecutionTrace::new();
            let err = hosted(store.clone())
                .with_ssh_runner(runner.clone())
                .execute_allowed(&aimed_at(host), &serde_json::json!({}), &[], &trace)
                .await
                .expect_err(host);
            assert!(matches!(err, GatewayError::Denied(ref m) if m.contains("public addresses only")), "{host}: {err:?}");
            assert!(runner.invocations().is_empty(), "{host}: the transport was never asked to dial");
            assert_eq!(ExecutionOutcome::classify(&trace, &err), ExecutionOutcome::Refused, "{host}");
        }

        let runner = Arc::new(MockSshRunner::new());
        hosted(store.clone())
            .with_ssh_runner(runner.clone())
            .execute_allowed(&aimed_at("ssh.example.com"), &serde_json::json!({}), &[], &ExecutionTrace::new())
            .await
            .expect("a public host is dialled");
        assert_eq!(runner.invocations().len(), 1);
        assert_eq!(runner.last_invocation().unwrap().egress, connectors::SshEgress::PublicOnly, "and screened again at the dial");

        // Unchanged on a gateway its owner runs: loopback is dialled, by whatever it resolves to.
        let runner = Arc::new(MockSshRunner::new());
        EnforcementService::new(store, Arc::new(MockHttpClient::new()))
            .with_ssh_runner(runner.clone())
            .execute_allowed(&aimed_at("127.0.0.1"), &serde_json::json!({}), &[], &ExecutionTrace::new())
            .await
            .expect("a self-run gateway still dials its own loopback");
        let dialled = runner.last_invocation().unwrap();
        assert_eq!((dialled.target.host.as_str(), dialled.egress), ("127.0.0.1", connectors::SshEgress::Unrestricted));
    }

    #[tokio::test]
    async fn a_command_printing_its_injected_token_returns_the_marker() {
        let token = "vercel_demo_api_token_value";
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        crate::seed::seed(store.as_ref()).unwrap();
        let runner = crate::connectors::MockCommandRunner::with_output(crate::connectors::CommandOutput {
            code: 1,
            stdout: format!("{token} is expired\n{{\"note\":\"VERCEL_TOKEN={token}\"}}"),
            stderr: String::new(),
        });
        let svc = EnforcementService::with_command_runner(store, Arc::new(MockHttpClient::new()), Arc::new(runner));
        let cap = permaura_connectors::Capability {
            id: "vercel-cli.whoami".into(),
            description: "Print the Vercel account the token belongs to".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: "vercel_acme".into(),
            secret_id: "sec_vercel".into(),
            kind: permaura_connectors::CapabilityKind::Command,
            command: Some(permaura_connectors::CommandSpec {
                program: "vercel".into(),
                args_template: vec!["whoami".into()],
                secret_env: "VERCEL_TOKEN".into(),
                allowed_placeholders: vec![],
            }),
            http: None,
            ssh: None,
        };

        let executed = svc
            .execute_allowed(&cap, &serde_json::json!({}), &permaura_core::default_redact_keys(), &ExecutionTrace::new())
            .await
            .unwrap();
        let redacted = executed.redacted.to_value_unbounded();
        let output = redacted["output"].as_str().unwrap();
        assert!(output.starts_with(&format!("{} is expired", permaura_core::SCRUBBED)), "{output}");
        assert!(!executed.redacted.get().contains(token));
        let diagnostic = executed.diagnostic.unwrap();
        assert!(!diagnostic.contains(token) && diagnostic.contains(permaura_core::SCRUBBED), "{diagnostic}");
    }

    /// The Vercel projection is the one place an upstream body still becomes a tree, charged to the memory budget after the call was sent.
    /// A budget with no room is an error that says the call was sent, and the raw body never reaches the agent in place of the projection.
    #[tokio::test]
    async fn a_projection_with_no_room_fails_closed_and_one_with_room_still_projects() {
        let body = serde_json::json!({ "envs": [{ "id": "env_1", "key": "DATABASE_URL", "type": "plain", "target": ["production"], "value": "postgres://user:pw@db/x" }] });
        let build = |pool_bytes: u64| {
            let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
            crate::seed::seed(store.as_ref()).unwrap();
            let http = Arc::new(MockHttpClient::with_response(crate::connectors::HttpResponse::json(200, body.clone())));
            let config = crate::limits::LimitsConfig {
                json_pool_bytes: pool_bytes,
                json_pool_wait: std::time::Duration::ZERO,
                ..crate::limits::LimitsConfig::default()
            };
            let svc = EnforcementService::new(store.clone(), http).with_memory_budget(crate::memory::MemoryBudget::from_config(&config));
            (svc, store.get_capability("vercel.env.read").unwrap().expect("the seeded capability"))
        };
        let params = serde_json::json!({ "project_id": "p" });

        let (svc, cap) = build(1024);
        let err = svc
            .execute_allowed(&cap, &params, &permaura_core::default_redact_keys(), &ExecutionTrace::new())
            .await
            .expect_err("no room for the projection's tree");
        assert!(err.to_string().contains("was sent"), "{err}");
        assert!(!err.to_string().contains("postgres://"), "{err}");

        let (svc, cap) = build(64 * 1024 * 1024);
        let executed = svc
            .execute_allowed(&cap, &params, &permaura_core::default_redact_keys(), &ExecutionTrace::new())
            .await
            .unwrap();
        let result = executed.redacted.to_value_unbounded();
        assert_eq!(result["envs"][0]["key"], "DATABASE_URL");
        assert!(result["envs"][0].get("value").is_none(), "the projection still drops the value: {result}");
        assert_eq!(svc.memory().pool().available_bytes(), svc.memory().pool().max_bytes(), "and its tree's room is given back");
    }

    /// Command output at its shipped cap is never refused for its shape on a hosted worker's memory budget, and its JSON is still redacted, as a stream.
    #[tokio::test]
    async fn command_json_output_at_its_cap_is_returned_whole_and_redacted() {
        let cap_bytes = crate::connectors::DEFAULT_COMMAND_MAX_OUTPUT_BYTES as usize;
        let mut stdout = String::from("[");
        let mut rows = 0;
        loop {
            let row = format!(r#"{{"id":{rows},"ok":true,"token":"t{rows}"}}"#);
            if stdout.len() + row.len() + 2 > cap_bytes {
                break;
            }
            if rows > 0 {
                stdout.push(',');
            }
            stdout.push_str(&row);
            rows += 1;
        }
        stdout.push(']');
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        crate::seed::seed(store.as_ref()).unwrap();
        let runner = crate::connectors::MockCommandRunner::with_output(crate::connectors::CommandOutput { code: 0, stdout, stderr: String::new() });
        let hosted = crate::memory::MemoryBudget::from_config(&crate::limits::LimitsConfig::defaults_for(true));
        let svc = EnforcementService::with_command_runner(store, Arc::new(MockHttpClient::new()), Arc::new(runner)).with_memory_budget(hosted);
        let cap = permaura_connectors::Capability {
            id: "vercel-cli.whoami".into(),
            description: "Print the Vercel account the token belongs to".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: "vercel_acme".into(),
            secret_id: "sec_vercel".into(),
            kind: permaura_connectors::CapabilityKind::Command,
            command: Some(permaura_connectors::CommandSpec {
                program: "vercel".into(),
                args_template: vec!["whoami".into()],
                secret_env: "VERCEL_TOKEN".into(),
                allowed_placeholders: vec![],
            }),
            http: None,
            ssh: None,
        };
        let executed = svc
            .execute_allowed(&cap, &serde_json::json!({}), &permaura_core::default_redact_keys(), &ExecutionTrace::new())
            .await
            .unwrap();
        assert_eq!(executed.status, 200);
        let redacted = executed.redacted.to_value_unbounded();
        let output = redacted["output"].as_array().expect("JSON output stays JSON");
        assert_eq!(output.len(), rows);
        assert_eq!(output[rows - 1]["token"], permaura_core::REDACTED);
        assert_eq!(output[rows - 1]["id"], rows - 1);
    }

    /// Delegate a `Store` method straight through to the wrapped [`MemoryStore`].
    macro_rules! delegate {
        ($( fn $name:ident ( $( $arg:ident : $ty:ty ),* ) -> $ret:ty; )*) => {
            $( fn $name(&self, $( $arg : $ty ),*) -> $ret { self.inner.$name($( $arg ),*) } )*
        };
    }

    /// A store that is entirely functional except that `gateway_meta` access can be made to fail on
    /// demand: the shape of a storage blip at exactly the wrong moment.
    ///
    /// Both directions matter and neither may degrade quietly. A failed READ is not a keyring that is
    /// EMPTY; collapsing the two would untrust every paired device and drop the approval floor back to
    /// `Approve` on nothing more than a transient fault. A failed WRITE is not a change that landed;
    /// reporting one as success leaves the caller believing a trust-root change holds while the next
    /// refresh reloads the stored value straight over it.
    struct FlakyMeta {
        inner: MemoryStore,
        reads_fail: AtomicBool,
        writes_fail: AtomicBool,
        audits_fail: AtomicBool,
        /// A secret compare-and-swap commits and then reports a failure, as a hosted store does when the upload fails.
        secret_swaps_commit_then_fail: AtomicBool,
        secret_swaps: std::sync::atomic::AtomicUsize,
        /// When set, every audit append and approval-row write records what `pool` has reserved as it is made.
        watched: std::sync::Mutex<Option<Watched>>,
    }

    /// A pool, and each write since it was watched with what the pool had reserved as it was made.
    type Watched = (Arc<crate::connectors::MemoryPool>, Vec<(String, u64)>);

    impl FlakyMeta {
        fn healthy() -> Self {
            FlakyMeta {
                inner: MemoryStore::new(),
                reads_fail: AtomicBool::new(false),
                writes_fail: AtomicBool::new(false),
                audits_fail: AtomicBool::new(false),
                secret_swaps_commit_then_fail: AtomicBool::new(false),
                secret_swaps: std::sync::atomic::AtomicUsize::new(0),
                watched: std::sync::Mutex::new(None),
            }
        }

        fn watch(&self, pool: Arc<crate::connectors::MemoryPool>) {
            *self.watched.lock().unwrap() = Some((pool, Vec::new()));
        }

        fn note(&self, write: String) {
            if let Some((pool, seen)) = self.watched.lock().unwrap().as_mut() {
                seen.push((write, pool.max_bytes() - pool.available_bytes()));
            }
        }

        /// Each write since the last call, with what the pool had reserved as it was made.
        fn writes(&self) -> Vec<(String, u64)> {
            self.watched.lock().unwrap().as_mut().map(|(_, seen)| std::mem::take(seen)).unwrap_or_default()
        }

        fn reads_fail() -> Self {
            let s = Self::healthy();
            s.reads_fail.store(true, Ordering::SeqCst);
            s
        }
    }

    impl Store for FlakyMeta {
        fn run_atomically(&self, f: &mut dyn FnMut(&dyn Store) -> Result<(), GatewayError>) -> Result<(), GatewayError> {
            f(self)
        }
        fn kind(&self) -> &'static str {
            self.inner.kind()
        }

        fn get_meta(&self, key: &str) -> Result<Option<String>, GatewayError> {
            if self.reads_fail.load(Ordering::SeqCst) {
                return Err(GatewayError::Internal("meta read failed".into()));
            }
            self.inner.get_meta(key)
        }

        fn put_meta(&self, key: &str, value: &str) -> Result<(), GatewayError> {
            if self.writes_fail.load(Ordering::SeqCst) {
                return Err(GatewayError::Internal("meta write failed".into()));
            }
            self.inner.put_meta(key, value)
        }

        fn append_audit_charged(&self, payload: AuditPayload, charge: Option<crate::store::GrantCharge>) -> Result<AuditEvent, GatewayError> {
            if self.audits_fail.load(Ordering::SeqCst) {
                return Err(GatewayError::Internal("audit append failed".into()));
            }
            self.note(format!("audit {}", payload.decision));
            self.inner.append_audit_charged(payload, charge)
        }

        fn put_approval(&self, approval: PendingApproval) -> Result<(), GatewayError> {
            self.note(format!("approval row {}", approval.status));
            self.inner.put_approval(approval)
        }

        fn put_secret_if_unchanged(
            &self,
            id: &str,
            expected: &permaura_core::SealedSecret,
            sealed: permaura_core::SealedSecret,
        ) -> Result<bool, GatewayError> {
            self.secret_swaps.fetch_add(1, Ordering::SeqCst);
            let swapped = self.inner.put_secret_if_unchanged(id, expected, sealed)?;
            if self.secret_swaps_commit_then_fail.load(Ordering::SeqCst) {
                return Err(GatewayError::StoreUnavailable("synthetic upload failure".into()));
            }
            Ok(swapped)
        }

        delegate! {
            fn put_agent(agent: Agent) -> Result<(), GatewayError>;
            fn get_agent(id: &str) -> Result<Option<Agent>, GatewayError>;
            fn list_agents() -> Result<Vec<Agent>, GatewayError>;
            fn delete_agent(id: &str) -> Result<bool, GatewayError>;
            fn put_session(session: Session) -> Result<(), GatewayError>;
            fn insert_session(session: Session) -> Result<bool, GatewayError>;
            fn touch_session(id: &str, token: &str, now: i64, extend_expiry_to: Option<i64>) -> Result<bool, GatewayError>;
            fn session_by_token(token: &str) -> Result<Option<Session>, GatewayError>;
            fn get_session(id: &str) -> Result<Option<Session>, GatewayError>;
            fn list_sessions() -> Result<Vec<Session>, GatewayError>;
            fn revoke_session(id: &str) -> Result<bool, GatewayError>;
            fn expire_session_by(id: &str, at: i64) -> Result<bool, GatewayError>;
            fn delete_live_sessions() -> Result<u64, GatewayError>;
            fn delete_session(id: &str) -> Result<bool, GatewayError>;
            fn delete_session_if(id: &str, dead: &dyn Fn(&Session) -> bool) -> Result<bool, GatewayError>;
            fn put_connection(connection: Connection) -> Result<(), GatewayError>;
            fn get_connection(id: &str) -> Result<Option<Connection>, GatewayError>;
            fn list_connections() -> Result<Vec<Connection>, GatewayError>;
            fn delete_connection(id: &str) -> Result<bool, GatewayError>;
            fn put_policy(policy: Policy) -> Result<(), GatewayError>;
            fn get_policy(id: &str) -> Result<Option<Policy>, GatewayError>;
            fn list_policies() -> Result<Vec<Policy>, GatewayError>;
            fn policies_for_connection(connection_id: &str) -> Result<Vec<Policy>, GatewayError>;
            fn delete_policy(id: &str) -> Result<bool, GatewayError>;
            fn put_grant(grant: Grant) -> Result<(), GatewayError>;
            fn get_grant(grant_id: &str) -> Result<Option<Grant>, GatewayError>;
            fn list_grants() -> Result<Vec<Grant>, GatewayError>;
            fn update_grant(grant: Grant) -> Result<bool, GatewayError>;
            fn delete_grant(grant_id: &str) -> Result<bool, GatewayError>;
            fn put_enrolment_code(code: EnrolmentCode) -> Result<(), GatewayError>;
            fn mint_enrolment_code(code: EnrolmentCode, now_ms: i64, live_max: usize) -> Result<(), GatewayError>;
            fn consume_enrolment_code(code: &str, now_ms: i64) -> Result<Option<EnrolmentCode>, GatewayError>;
            fn enrolment_code_redeemable(code: &str, now_ms: i64) -> Result<bool, GatewayError>;
            fn delete_unconsumed_enrolment_codes() -> Result<u64, GatewayError>;
            fn put_secret(record: SecretRecord) -> Result<(), GatewayError>;
            fn get_secret(id: &str) -> Result<Option<SecretRecord>, GatewayError>;
            fn list_secret_ids() -> Result<Vec<String>, GatewayError>;
            fn delete_secret(id: &str) -> Result<bool, GatewayError>;
            fn put_secret_custody(custody: SecretCustody) -> Result<(), GatewayError>;
            fn get_secret_custody(secret_id: &str) -> Result<Option<SecretCustody>, GatewayError>;
            fn list_secret_custody() -> Result<Vec<SecretCustody>, GatewayError>;
            fn delete_secret_custody(secret_id: &str) -> Result<bool, GatewayError>;
            fn put_capability(cap: Capability) -> Result<(), GatewayError>;
            fn get_capability(id: &str) -> Result<Option<Capability>, GatewayError>;
            fn list_capabilities() -> Result<Vec<Capability>, GatewayError>;
            fn delete_capability(id: &str) -> Result<bool, GatewayError>;
            fn get_approval(id: &str) -> Result<Option<PendingApproval>, GatewayError>;
            fn set_approval_status(id: &str, status: &str) -> Result<Option<PendingApproval>, GatewayError>;
            fn list_approvals(status: Option<&str>) -> Result<Vec<PendingApproval>, GatewayError>;
            fn put_connector_manifest(manifest: InstalledManifest) -> Result<(), GatewayError>;
            fn get_connector_manifest(id: &str) -> Result<Option<InstalledManifest>, GatewayError>;
            fn list_connector_manifests() -> Result<Vec<InstalledManifest>, GatewayError>;
            fn delete_connector_manifest(id: &str) -> Result<bool, GatewayError>;
            fn claim_once(scope: &str, jti: &str, expires_at_ms: i64) -> Result<bool, GatewayError>;
            fn audit_events(limit: Option<usize>) -> Result<Vec<AuditEvent>, GatewayError>;
            fn audit_len() -> Result<u64, GatewayError>;
            fn put_call_diagnostic(diagnostic: crate::store::CallDiagnostic) -> Result<(), GatewayError>;
            fn call_diagnostics(from_seq: u64) -> Result<Vec<crate::store::CallDiagnostic>, GatewayError>;
            fn purge_call_diagnostics() -> Result<u64, GatewayError>;
            fn audit_events_from(from_seq: u64, limit: usize) -> Result<Vec<AuditEvent>, GatewayError>;
            fn prune_audit_to(end_seq: u64, base_hash: &str, segment_head: &str) -> Result<u64, GatewayError>;
            fn seal_audit_segment(draft: permaura_core::audit::AuditSegmentDraft) -> Result<permaura_core::audit::AuditSegment, GatewayError>;
            fn seal_audit_index(index: permaura_core::audit::AuditArchiveIndex, written_at: &str) -> Result<permaura_core::audit::AuditArchiveIndex, GatewayError>;
            fn audit_verifying_key() -> Result<[u8; 32], GatewayError>;
            fn count_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
            fn read_grant_usage(windows: &[crate::store::GrantWindow<'_>]) -> Result<crate::store::GrantUsageCounts, GatewayError>;
            fn grant_usage_series(grant_id: &str, since_ms: i64, bucket_ms: i64, buckets: usize) -> Result<Vec<u64>, GatewayError>;
            fn rebuild_grant_usage(archived: &mut dyn Iterator<Item = Result<AuditEvent, GatewayError>>) -> Result<u64, GatewayError>;
            fn verify_audit() -> Result<Option<u64>, GatewayError>;
            fn audit_boundary() -> Result<Option<permaura_core::audit::AuditBoundary>, GatewayError>;
            fn fork_audit_epoch(epoch: u64, restore_id: &str) -> Result<bool, GatewayError>;
        }
    }

    /// A call that reads GraphQL documents holds nothing in the memory pool past its params' room at any store write after its gate: the denial or refusal it records, the row it is held as, the terminal event its execution closes with, and, once approved, the row it settles as and its terminal event beside the room its approval took. On a hosted worker each of those writes can wait on a snapshot upload. That includes the room taken for aliases its response is redacted under, given back when the execution returns.
    #[tokio::test]
    async fn a_graphql_call_holds_only_its_params_room_through_the_store_writes_after_its_gate() {
        use crate::connectors::{AuthScheme, HttpMethod, HttpSpec};
        let store = Arc::new(FlakyMeta::healthy());
        crate::seed::seed(store.as_ref()).unwrap();
        for id in ["github.pull_requests.list", "github.pull_requests.create", "braintree.transactions.refund"] {
            let mut cap = store.get_capability(id).unwrap().unwrap();
            cap.http = Some(HttpSpec {
                method: HttpMethod::Post,
                base_url: "https://api.probe.test".into(),
                path: "/v1/search".into(),
                body_params: vec!["query".into()],
                auth: AuthScheme::Bearer,
                ..HttpSpec::default()
            });
            // Filed as imported: a GitHub or Braintree connection sends its credential to its own host only.
            let mut connection = store.get_connection(&cap.resource).unwrap().unwrap();
            connection.connector = "openapi".into();
            store.put_connection(connection).unwrap();
            store.put_capability(cap).unwrap();
        }
        let budget = crate::memory::MemoryBudget::from_config(&crate::limits::LimitsConfig::defaults_for(true));
        let pool = budget.pool().clone();
        let resolution_bytes = budget.resolution_bytes();
        let svc = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new())).with_memory_budget(budget);
        let session = store.get_session("sess_demo").unwrap().unwrap();
        let kib = |bytes: u64| bytes.div_ceil(1024) * 1024;
        let params_room = 256 * 1024;
        let aliases = format!("{{{}}}", "a:b ".repeat(16 * 1024));
        let secrets = format!("{{{}}}", (0..600).map(|n| format!("s{n}: secret")).collect::<Vec<_>>().join(" "));
        assert!(crate::connectors::response_alias_room("github", &store.get_capability("github.pull_requests.list").unwrap().unwrap(), &serde_json::json!({ "query": secrets }), &permaura_core::default_redact_keys()) > crate::connectors::UNCHARGED_ALIAS_ROOM);
        let after_gate = |writes: Vec<(String, u64)>| writes.into_iter().filter(|(write, _)| write != "audit attempt").collect::<Vec<_>>();

        let mut held = None;
        for (id, document, expect) in [
            ("github.pull_requests.list", aliases.as_str(), "audit allow"),
            ("github.pull_requests.list", secrets.as_str(), "audit allow"),
            ("github.pull_requests.list", "mutation { merge }", "audit deny"),
            ("braintree.transactions.refund", aliases.as_str(), "audit deny"),
            ("github.pull_requests.create", aliases.as_str(), "approval row pending"),
        ] {
            store.watch(pool.clone());
            let params = serde_json::json!({ "query": document });
            let charge = pool.reserve(params_room, std::time::Duration::ZERO).await.unwrap();
            let outcome = svc
                .invoke_admitted(&session, id, crate::memory::AgentParams::charged(params, charge), None, ExecutionLocation::LocalOnly)
                .await
                .unwrap();
            if let InvokeOutcome::RequiresApproval { approval, .. } = &outcome {
                held = Some(approval.id.clone());
            }
            let writes = after_gate(store.writes());
            assert!(writes.iter().any(|(write, _)| write == expect), "{id} {document:.20}: {writes:?}");
            for (write, used) in &writes {
                assert_eq!(*used, params_room, "{id} {document:.20}: {write} with {used} bytes reserved");
            }
            assert_eq!(pool.available_bytes(), pool.max_bytes(), "{id}: all of it given back");
        }

        let id = held.expect("the create call is held");
        let text = store.get_approval(&id).unwrap().unwrap().params;
        let approval_room = kib(crate::memory::held_room(text.get().as_bytes()) + resolution_bytes);
        store.watch(pool.clone());
        svc.resolve_approval(&id, true, "bearer", Some("operator")).await.unwrap();
        let writes = after_gate(store.writes());
        assert!(writes.iter().any(|(write, _)| write == "approval row approved"), "{writes:?}");
        for (write, used) in &writes {
            assert_eq!(*used, approval_room, "approving: {write} with {used} bytes reserved");
        }
        assert_eq!(pool.available_bytes(), pool.max_bytes());
    }

    /// A held control-plane change past its deadline, as `hold_mutation_approval` stores one.
    fn expired_hold(id: &str) -> PendingApproval {
        let created_at = now_ms() - crate::store::CONTROL_PLANE_HOLD_TTL_MS - 60_000;
        PendingApproval {
            id: id.into(),
            session_id: String::new(),
            capability: crate::rest::POLICY_WRITE_CAP.into(),
            resource: crate::store::CONTROL_PLANE_RESOURCE.into(),
            message: "held".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "kind": "agent_delete", "agent_id": "agt_gone" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at,
            expires_at: Some(created_at + crate::store::CONTROL_PLANE_HOLD_TTL_MS),
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "device_signed".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    fn expiry_records(store: &dyn Store, id: &str) -> usize {
        store
            .audit_events(None)
            .unwrap()
            .iter()
            .filter(|e| e.payload.summary["approval_id"] == id && e.payload.summary["method"] == "expired")
            .count()
    }

    /// A rotation the store committed and could not carry (a hosted upload that failed) is written once in a round rather than retried into three more snapshot uploads, and nothing is parked.
    #[tokio::test]
    async fn a_rotation_committed_before_its_upload_failed_is_written_once() {
        let store = Arc::new(FlakyMeta::healthy());
        let seal_of = |v: &str| seal(Cipher::Aes256Gcm, vault_passphrase(), v.as_bytes()).unwrap();
        let expected = seal_of("before");
        store.put_secret(SecretRecord { id: "sec_rot".into(), sealed: expected.clone(), metadata: Default::default() }).unwrap();
        store.secret_swaps_commit_then_fail.store(true, Ordering::SeqCst);
        let pending = PendingRotations::default();
        let rotated = seal_of("after");
        assert!(EnforcementService::write_rotation(store.as_ref(), &pending, "sec_rot", &expected, rotated.clone()).await);
        assert_eq!(store.secret_swaps.load(Ordering::SeqCst), 1, "one write, so one upload");
        assert!(pending.lock().unwrap().is_empty());
        assert_eq!(store.get_secret("sec_rot").unwrap().unwrap().sealed, rotated);
    }

    /// The owner binding used to move before the audit append, so an append that failed left the pin moved with no record, and every later check-in found the owner already bound and recorded nothing until a restart reverted it. The audit comes first: a failed append moves nothing, and the next check-in moves it and records it once.
    #[tokio::test]
    async fn an_owner_move_the_audit_could_not_record_does_not_happen() {
        let store = Arc::new(FlakyMeta::healthy());
        let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
            public_url: "https://g-repin.permaura.test".into(),
            mcp_resource: "https://g-repin.permaura.test/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.test/api/auth".into(),
            jwks_uri: "https://permaura.test/api/auth/jwks".into(),
            owner_sub: Some("user_old".into()),
        }));
        let backend = crate::backend::build_backend(store.clone());
        let svc = EnforcementService::from_components(
            store.clone(),
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            Some(oauth.clone()),
        );
        let moves = || store.audit_events(None).unwrap().iter().filter(|e| e.payload.action == OWNER_REPIN_ACTION).count();

        store.audits_fail.store(true, Ordering::SeqCst);
        assert!(svc.repin_owner("user_new", true, None, None).is_err());
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_old"), "a move that could not be recorded does not happen");
        assert_eq!(moves(), 0);

        store.audits_fail.store(false, Ordering::SeqCst);
        assert!(svc.repin_owner("user_new", true, None, None).unwrap(), "the next check-in moves it");
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_new"));
        assert!(!svc.repin_owner("user_new", true, None, None).unwrap(), "already bound");
        assert_eq!(moves(), 1, "recorded once");
    }

    /// Once `permaura remote disable` has withdrawn the resource server, a check-in naming a new owner moves no binding and writes nothing back into the config file it cleared, and no token verifies.
    #[tokio::test]
    async fn a_withdrawn_resource_server_follows_no_owner_and_verifies_nothing() {
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
            public_url: "https://g-disable.permaura.test".into(),
            mcp_resource: "https://g-disable.permaura.test/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.test/api/auth".into(),
            jwks_uri: "https://permaura.test/api/auth/jwks".into(),
            owner_sub: Some("user_old".into()),
        }));
        let backend = crate::backend::build_backend(store.clone());
        let svc = EnforcementService::from_components(
            store.clone(),
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            Some(oauth.clone()),
        );
        oauth.withdraw();
        let config = std::env::temp_dir().join(format!("permaura-disable-repin-{}.toml", std::process::id()));
        std::fs::write(&config, "# cleared by remote disable\n").unwrap();
        assert!(!svc.repin_owner("user_new", true, Some(&config), None).unwrap(), "nothing moves");
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_old"));
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "# cleared by remote disable\n", "the cleared file stays cleared");
        assert_eq!(oauth.verify("a.b.c", 0).unwrap_err(), crate::oauth::REMOTE_ACCESS_OFF);
        let _ = std::fs::remove_file(&config);
    }

    /// A kill switch the store cannot record still switches. With every audit append failing, `POST /v1/remote/disable` withdraws the resource server and stops the connector, and answers that it could not record it.
    #[cfg(unix)]
    #[tokio::test]
    async fn remote_disable_still_switches_when_the_store_cannot_record_it() {
        use tower::ServiceExt as _;
        let _turn = crate::tunnel::tests::STOPPING.lock().await;
        let store = Arc::new(FlakyMeta::healthy());
        let token = crate::mint_operator_session(store.as_ref()).unwrap();
        let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
            public_url: "https://g-audit03.permaura.test".into(),
            mcp_resource: "https://g-audit03.permaura.test/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.test/api/auth".into(),
            jwks_uri: "https://permaura.test/api/auth/jwks".into(),
            owner_sub: Some("user_audit03".into()),
        }));
        let backend = crate::backend::build_backend(store.clone());
        let svc = EnforcementService::from_components(
            store.clone(),
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            Some(oauth.clone()),
        );
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let slot: crate::tunnel::ConnectorSlot = Arc::new(std::sync::Mutex::new(Some(child)));
        let state = crate::AppState::new(svc).with_tunnel(slot.clone());
        store.audits_fail.store(true, Ordering::SeqCst);

        let resp = crate::build_router(state, "127.0.0.1:7376".parse().unwrap())
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/remote/disable")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["connector"], "stopped", "{body}");
        assert_eq!(body["audited"], false, "{body}");
        assert!(body["audit_error"].as_str().is_some_and(|e| !e.is_empty()), "{body}");
        assert!(oauth.is_withdrawn(), "the resource server is withdrawn although nothing could record it");
        assert!(slot.lock().unwrap().is_none(), "the connector is stopped although nothing could record it");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remote_disable_finishes_recording_after_its_request_is_canceled() {
        use tower::ServiceExt as _;
        let _turn = crate::tunnel::tests::STOPPING.lock().await;
        let store = Arc::new(FlakyMeta::healthy());
        let token = crate::mint_operator_session(store.as_ref()).unwrap();
        let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
            public_url: "https://g-audit03.permaura.test".into(),
            mcp_resource: "https://g-audit03.permaura.test/mcp".into(),
            public_url_aliases: Vec::new(),
            issuer: "https://permaura.test/api/auth".into(),
            jwks_uri: "https://permaura.test/api/auth/jwks".into(),
            owner_sub: Some("user_audit03".into()),
        }));
        let backend = crate::backend::build_backend(store.clone());
        let svc = EnforcementService::from_components(
            store.clone(),
            Arc::new(MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            Some(oauth.clone()),
        );
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let slot: crate::tunnel::ConnectorSlot = Arc::new(std::sync::Mutex::new(Some(child)));
        let state = crate::AppState::new(svc).with_tunnel(slot.clone());

        let (held, ready) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let waiting_slot = slot.clone();
        let waiter = std::thread::spawn(move || {
            let _lock = waiting_slot.lock().unwrap();
            held.send(()).unwrap();
            released.recv().unwrap();
        });
        ready.recv().unwrap();
        let request = axum::http::Request::builder().method("POST").uri("/v1/remote/disable")
            .header("authorization", format!("Bearer {token}")).body(axum::body::Body::empty()).unwrap();
        let task = tokio::spawn(crate::build_router(state, "127.0.0.1:49151".parse().unwrap()).oneshot(request));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !oauth.is_withdrawn() { tokio::task::yield_now().await; }
        }).await.unwrap();
        task.abort();
        let _ = task.await;
        release.send(()).unwrap();
        waiter.join().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if store.audit_events(None).unwrap().iter().any(|e| e.payload.action == crate::rest::REMOTE_DISABLE_ACTION) { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("the detached kill switch still records its result");
        assert!(slot.lock().unwrap().is_none());
    }

    /// An expiry whose audit record could not be written is not left claimed and pending for ever. The claim and the expired row land together with a note that the record is owed, and the next sweep writes the record, once.
    #[tokio::test]
    async fn an_expiry_whose_record_failed_is_recorded_by_the_next_sweep() {
        let store = Arc::new(FlakyMeta::healthy());
        let svc = hosted(store.clone());
        store.put_approval(expired_hold("appr_owed")).unwrap();

        store.audits_fail.store(true, Ordering::SeqCst);
        assert_eq!(svc.retire_expired_holds(now_ms()).unwrap(), vec!["appr_owed".to_string()]);
        let row = store.get_approval("appr_owed").unwrap().unwrap();
        assert_eq!(row.status, crate::store::APPROVAL_EXPIRED, "retired, not left pending");
        assert_eq!(expiry_records(store.as_ref(), "appr_owed"), 0);
        assert!(svc.owed_expiry_records().unwrap().contains("appr_owed"));
        assert!(svc.retire_expired_holds(now_ms()).unwrap().is_empty(), "nothing new to retire");
        assert!(svc.owed_expiry_records().unwrap().contains("appr_owed"), "still owed while appends fail");

        store.audits_fail.store(false, Ordering::SeqCst);
        assert!(svc.retire_expired_holds(now_ms()).unwrap().is_empty());
        assert_eq!(expiry_records(store.as_ref(), "appr_owed"), 1, "the next sweep writes the record");
        assert!(svc.owed_expiry_records().unwrap().is_empty());
        svc.retire_expired_holds(now_ms()).unwrap();
        assert_eq!(expiry_records(store.as_ref(), "appr_owed"), 1, "once");
    }

    /// The unit is the claim, the row and the note: when the note cannot be written nothing of it lands, so the hold stays pending and unclaimed, and the next sweep retires it.
    #[tokio::test]
    async fn an_expiry_that_could_not_be_written_is_retried_whole() {
        let store = Arc::new(FlakyMeta::healthy());
        let svc = hosted(store.clone());
        store.put_approval(expired_hold("appr_whole")).unwrap();
        store.writes_fail.store(true, Ordering::SeqCst);
        assert!(svc.retire_expired_holds(now_ms()).is_err());
        store.writes_fail.store(false, Ordering::SeqCst);
        let row = store.get_approval("appr_whole").unwrap().unwrap();
        if row.status == "pending" {
            assert_eq!(svc.retire_expired_holds(now_ms()).unwrap(), vec!["appr_whole".to_string()]);
        }
        assert_eq!(store.get_approval("appr_whole").unwrap().unwrap().status, crate::store::APPROVAL_EXPIRED);
        assert_eq!(expiry_records(store.as_ref(), "appr_whole"), 1);
    }

    /// The bug this whole change closes: on Cloud Run the filesystem is gone by the next cold start,
    /// so a hosted pairing that lived only on disk would be forgotten, and with it the floor, which
    /// would silently fall back to `approve`.
    #[test]
    fn a_store_backed_pairing_and_floor_survive_a_cold_start() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let a = hosted(store.clone());
        assert!(a.trust_approver_key_durable("device:phone", &pubkey(1)).unwrap());
        a.set_approval_floor(Some(ApprovalFloor::Approve)).unwrap();

        // A brand-new process over the same store: the container was reaped and rescheduled.
        let b = hosted(store.clone());
        assert_eq!(
            b.approver_keyring_snapshot().trusted_key("device:phone"),
            Some(pubkey(1).as_str()),
        );
        assert!(b.any_device_enrolled());
        assert!(b.any_device_trusted());
        assert_eq!(
            b.approval_floor(),
            ApprovalFloor::Approve,
            "the operator's explicit opt-down must survive the restart, not just the keyring",
        );

        // Clearing the override is recorded as absence, not as a value nothing can parse.
        b.set_approval_floor(None).unwrap();
        let c = hosted(store.clone());
        assert_eq!(
            c.approval_floor(),
            ApprovalFloor::Approve,
            "with no override the policy decides which actions need a signature, not enrolment",
        );
        assert!(
            c.control_plane_hold_required(true),
            "clearing the override is not the explicit opt-down, so the broker guard stays armed",
        );
    }

    /// Pairing a device makes the `device_signed` rung RESOLVABLE. It does not decide what every
    /// other action needs; the policy already did that, and enrolment overriding it silently is what
    /// made the policy editor a lie and pairing a surprise.
    #[test]
    fn pairing_a_device_no_longer_raises_the_floor_by_itself() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        assert_eq!(svc.approval_floor(), ApprovalFloor::Approve);

        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(11)).unwrap());
        assert_eq!(
            svc.approval_floor(),
            ApprovalFloor::Approve,
            "the policy's per-action rung decides; the blanket is offered, not assumed",
        );
        // The protections that were never about approvals must not have moved with it.
        assert!(svc.control_plane_hold_required(true));
        assert!(svc.vault_export_hold_required());

        // And raising it is one call, which is what the pairing flow offers.
        svc.set_approval_floor(Some(ApprovalFloor::DeviceSigned)).unwrap();
        assert!(svc.require_device_signed_approval());
    }

    /// The opt-down is the one thing that disarms the guards, and it stays that way. Reaching it
    /// costs a step-up and, while any usable device remains, that device's signature.
    #[test]
    fn only_an_explicit_opt_down_disarms_the_broker_guard() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(12)).unwrap());
        assert!(svc.control_plane_hold_required(true));

        svc.set_approval_floor(Some(ApprovalFloor::Approve)).unwrap();
        assert!(
            !svc.control_plane_hold_required(true),
            "an opt-down that left the control plane frozen would buy a stranded tenant nothing",
        );
        assert!(!svc.vault_export_hold_required());
    }

    /// THE UPGRADE. A gateway that already had a device enrolled has been running with blanket
    /// device-signed approvals. Changing the default must not loosen it underneath an operator who
    /// never asked and would not be told, so the floor it was already enforcing is written down.
    #[test]
    fn an_existing_pairing_keeps_the_floor_it_was_running_with() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let before = hosted(store.clone());
        assert!(before.trust_approver_key_durable("device:phone", &pubkey(13)).unwrap());
        drop(before);

        // The upgrade: a new process over the same store, doing what startup does.
        let after = hosted(store.clone());
        after.adopt_enrolment_floor();
        assert!(
            after.require_device_signed_approval(),
            "an install that was blanket-signed yesterday is blanket-signed today",
        );

        // Written down, not re-derived: the next process must not depend on running this again.
        let next = hosted(store);
        assert!(next.require_device_signed_approval());
    }

    /// A gateway that never paired anything has nothing to preserve, and must not be handed a floor
    /// it never had: that would be a tightening nobody asked for, arriving in a patch release.
    #[test]
    fn adopting_the_enrolment_floor_leaves_an_unpaired_gateway_alone() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        svc.adopt_enrolment_floor();
        assert_eq!(svc.approval_floor(), ApprovalFloor::Approve);
        assert!(!svc.control_plane_hold_required(true));
    }

    /// An operator who had already opted down keeps that answer. Adoption fills an ABSENT floor; it
    /// must never overwrite a decision someone paid a step-up to make.
    #[test]
    fn adopting_the_enrolment_floor_never_overwrites_an_explicit_choice() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(14)).unwrap());
        svc.set_approval_floor(Some(ApprovalFloor::Approve)).unwrap();

        svc.adopt_enrolment_floor();
        assert_eq!(svc.approval_floor(), ApprovalFloor::Approve);
    }

    /// A device paired after the adoption has run belongs to the policy-decides world it exists to leave
    /// alone: pairing does not raise the floor, and neither may the restart after it.
    #[test]
    fn a_device_paired_after_the_adoption_keeps_policy_deciding_across_a_restart() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let first = hosted(store.clone());
        first.adopt_enrolment_floor();
        assert!(first.trust_approver_key_durable("device:phone", &pubkey(15)).unwrap());
        assert_eq!(first.stored_approval_floor(), None, "pairing does not raise the floor");
        drop(first);

        let restarted = hosted(store);
        restarted.adopt_enrolment_floor();
        assert_eq!(restarted.stored_approval_floor(), None, "nor does the restart after it");
        assert_eq!(restarted.approval_floor(), ApprovalFloor::Approve);
    }

    /// The upgrade wrote the floor the gateway had; an owner who has since cleared that override chose
    /// policy-decides, and a restart must not write the blanket floor back over the choice.
    #[test]
    fn an_override_cleared_after_the_adoption_stays_cleared_across_a_restart() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let before = hosted(store.clone());
        assert!(before.trust_approver_key_durable("device:phone", &pubkey(16)).unwrap());
        drop(before);

        let upgraded = hosted(store.clone());
        upgraded.adopt_enrolment_floor();
        assert_eq!(upgraded.stored_approval_floor(), Some(ApprovalFloor::DeviceSigned));
        upgraded.set_approval_floor(None).unwrap();
        drop(upgraded);

        let restarted = hosted(store);
        restarted.adopt_enrolment_floor();
        assert_eq!(restarted.stored_approval_floor(), None);
    }

    /// THE PAIRING THAT LOOKED LIKE IT HAD NOT HAPPENED. A hosted worker runs several instances over
    /// one store. Instance A pairs a device; instance B answers the next `GET /v1/devices`. If the
    /// read behind `is_trusted` never re-reads the store, B reports the device untrusted and the
    /// person who just paired it sees it vanish when they leave the screen and come back.
    #[test]
    fn another_instance_reports_a_pairing_it_did_not_perform() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let a = hosted(store.clone());
        let b = hosted(store.clone());
        assert!(!b.approver_key_trusted("device:phone"));

        assert!(a.trust_approver_key_durable("device:phone", &pubkey(21)).unwrap());

        // B's snapshot predates the write. Whether it re-reads is the whole question.
        b.expire_keyring_cache_for_test();
        assert!(
            b.approver_key_trusted("device:phone"),
            "the device list must report what the store holds, not one instance's stale snapshot",
        );
        assert!(
            b.trusted_approver_key("device:phone").is_some(),
            "and so must the read `enroll_device` gates the device-signature requirement on",
        );
    }

    /// The legitimate fresh-worker case. An unwritten row is not a failure and must not be treated
    /// as one, or a tenant's very first boot would crash-loop.
    #[test]
    fn a_fresh_hosted_worker_loads_an_empty_keyring() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let (keyring, floor) =
            EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store)
                .expect("an unwritten row is the fresh-worker case, not a failure");
        assert!(!keyring.ever_enrolled());
        assert!(floor.is_none());
        assert_eq!(hosted(store).approval_floor(), ApprovalFloor::Approve);
    }

    #[test]
    fn a_store_read_error_fails_rather_than_degrading() {
        let store: Arc<dyn Store> = Arc::new(FlakyMeta::reads_fail());
        EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store)
            .expect_err("an unreadable keyring row must not be served as an empty keyring");
    }

    /// A self-run gateway used to keep its pairings in memory unless a keyring path was
    /// configured, and nothing configured one, so a restart silently untrusted every device and
    /// dropped the floor to bearer-only. The default is now the store, for every placement.
    #[test]
    fn a_self_run_pairing_survives_the_service_being_rebuilt_over_the_same_store() {
        assert!(
            matches!(EnforcementService::keyring_persistence_from_env(), KeyringPersistence::Store),
            "with no PERMAURA_APPROVER_KEYS_PATH the store is the default, hosted or not"
        );
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let first = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()));
        assert!(first.trust_approver_key_durable("device:phone", &pubkey(7)).unwrap());
        assert!(first.control_plane_hold_required(true));
        drop(first);
        let second = EnforcementService::new(store, Arc::new(MockHttpClient::new()));
        assert!(second.trusted_approver_key("device:phone").is_some(), "the pairing outlived the process");
        assert!(
            second.control_plane_hold_required(true),
            "and so did the hold it implies; the floor is no longer the observable for that, since \
             enrolment does not raise it, but the guard it arms is unchanged",
        );
    }

    /// A host-side `permaura approver reset` clears the row to the empty string, which must read as
    /// nothing paired rather than as a corrupt keyring that refuses to start.
    #[test]
    fn a_cleared_keyring_row_is_a_fresh_keyring_not_a_refusal() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store.put_meta(APPROVER_KEYRING_META, "").unwrap();
        let (keyring, _) =
            EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store).unwrap();
        assert!(!keyring.ever_enrolled());
    }

    fn scratch_keyring_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("permaura-keyring-{tag}-{}-{nanos}", std::process::id())).join("approver-keys.json")
    }

    /// The file backend used to read a damaged keyring as an empty one and start with no
    /// device protection. A missing file is still a fresh gateway; a present file that does not parse
    /// is a refusal.
    #[test]
    fn a_damaged_keyring_file_refuses_to_load_but_a_missing_one_is_fresh() {
        let keys = scratch_keyring_path("damaged");
        let persistence = KeyringPersistence::File { keys: keys.clone(), floor: keys.with_extension("floor") };
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        let (fresh, floor) = EnforcementService::load_persisted_keyring(&persistence, &store).unwrap();
        assert!(!fresh.ever_enrolled() && floor.is_none(), "no file is a fresh gateway");

        let mut kr = ApproverKeyring::new();
        assert!(kr.add("device:phone", &pubkey(3)));
        kr.save(&keys).unwrap();
        let (loaded, _) = EnforcementService::load_persisted_keyring(&persistence, &store).unwrap();
        assert!(loaded.trusted_key("device:phone").is_some(), "a saved keyring round-trips");

        std::fs::write(&keys, b"{").unwrap();
        EnforcementService::load_persisted_keyring(&persistence, &store)
            .expect_err("a truncated keyring must not load as an unpaired gateway");

        std::fs::write(&keys, b"{}").unwrap();
        std::fs::write(keys.with_extension("floor"), b"sideways").unwrap();
        EnforcementService::load_persisted_keyring(&persistence, &store)
            .expect_err("an unreadable floor override is a trust-root setting nobody chose");
        let _ = std::fs::remove_dir_all(keys.parent().unwrap());
    }

    #[test]
    fn a_corrupt_keyring_row_fails_rather_than_degrading() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store.put_meta(APPROVER_KEYRING_META, "{ this is not json").unwrap();
        EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store)
            .expect_err("an unparseable keyring row must not be served as an empty keyring");
    }

    #[test]
    fn an_unrecognised_floor_value_fails_rather_than_being_guessed_at() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        store.put_meta(APPROVAL_FLOOR_META, "whatever_comes_next").unwrap();
        EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store)
            .expect_err("a trust-root setting this build does not understand must not be assumed");

        // The empty string is how a clear is written, and must read back as "no override".
        store.put_meta(APPROVAL_FLOOR_META, "").unwrap();
        let (_, floor) =
            EnforcementService::load_persisted_keyring(&KeyringPersistence::Store, &store)
                .expect("a cleared override is absence, not corruption");
        assert!(floor.is_none());
    }

    /// The `File` arm must keep swallowing a missing file: on a self-run box that legitimately means
    /// "nothing paired yet", the disk is not shared with another instance, and failing there would
    /// break every existing install on its first boot.
    #[test]
    fn a_missing_keyring_file_still_means_nothing_paired() {
        let dir = std::env::temp_dir().join(format!("permaura-keyring-{}", short_id()));
        let persistence = KeyringPersistence::File {
            keys: dir.join("approver-keys.json"),
            floor: dir.join("approver-keys.floor"),
        };
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let (keyring, floor) = EnforcementService::load_persisted_keyring(&persistence, &store)
            .expect("a self-run gateway with no keyring file has simply paired nothing");
        assert!(!keyring.ever_enrolled());
        assert!(floor.is_none());
    }

    /// Revoking the only device must not leave a worker able to *require* a co-signature nothing can
    /// give. On a hosted worker there is no host to pair from, so that state is unrecoverable.
    #[test]
    fn any_device_trusted_is_false_once_every_device_is_revoked() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(2)).unwrap());
        assert!(svc.any_device_trusted());

        svc.revoke_approver_key("device:phone").unwrap();
        assert!(!svc.any_device_trusted(), "a revoked key cannot co-sign the next enrolment");
        assert!(
            svc.any_device_enrolled(),
            "the sticky enrolment flag must stay set: the default-on floor depends on it",
        );
        assert!(
            svc.control_plane_hold_required(true),
            "revoking the last device does not disarm the broker guard; only an explicit opt-down does",
        );
    }

    /// The multi-instance failure: instance B holds an empty keyring while instance A pairs. Without
    /// the refresh, B's `approval_floor()` stays at `approve` and B accepts a bearer-only resolution
    /// the tenant believes is closed.
    #[test]
    fn an_instance_picks_up_a_pairing_made_on_another() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let a = hosted(store.clone());
        let b = hosted(store.clone());
        assert!(!b.any_device_trusted());
        assert_eq!(b.approval_floor(), ApprovalFloor::Approve);

        assert!(a.trust_approver_key_durable("device:phone", &pubkey(3)).unwrap());

        b.refresh_keyring_now();
        assert!(b.any_device_trusted());
        assert!(
            b.control_plane_hold_required(true),
            "a stale empty keyring is what would leave this unguarded: the fail-open being closed",
        );
    }

    /// THE BLIND-OVERWRITE FAIL-OPEN. The keyring is serialised WHOLE on every write, so a mutation
    /// applied to a stale snapshot writes that snapshot over everything every other instance has done.
    ///
    /// Instance B has never seen either pairing instance A made. It revokes one device, the most
    /// ordinary console action there is. If the revocation reads its own five-second-old snapshot
    /// instead of the store, B writes an EMPTY keyring over the row: both pairings vanish,
    /// `ever_enrolled()` goes false, and `approval_floor()` drops from `device_signed` back to
    /// `approve`, re-opening bearer-only approval resolution on a tenant who believes it is closed.
    /// The revocation must land, and nothing else may move.
    #[test]
    fn a_revocation_from_a_stale_instance_cannot_erase_another_instances_pairings() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let a = hosted(store.clone());
        let b = hosted(store.clone());
        assert!(!b.any_device_trusted(), "B starts out with the empty snapshot it loaded at boot");

        assert!(a.trust_approver_key_durable("device:phone", &pubkey(6)).unwrap());
        assert!(a.trust_approver_key_durable("device:watch", &pubkey(7)).unwrap());

        b.revoke_approver_key("device:watch").unwrap();

        // A third instance reads the row cold, the only honest view of what B actually wrote.
        let c = hosted(store.clone());
        assert_eq!(
            c.approver_keyring_snapshot().trusted_key("device:phone"),
            Some(pubkey(6).as_str()),
            "a revocation of one device must not untrust another instance's pairing",
        );
        assert!(
            c.approver_keyring_snapshot().trusted_key("device:watch").is_none(),
            "the revocation itself must still have landed",
        );
        assert!(c.any_device_trusted());
        assert!(
            c.control_plane_hold_required(true),
            "an emptied row is what would leave this unguarded: the silent fail-open being closed",
        );
    }

    /// The same section from the other direction: a WRITE must re-read first, so an instance that has
    /// never seen another's pairing cannot enrol its own key over the top of it.
    ///
    /// It also pins where the refresh clock is allowed to move. The stamp a keyring write leaves is
    /// earned by the read that opened its critical section, which is exactly what this asserts: after
    /// B's own write, B can see A's pairing without any further refresh.
    #[test]
    fn a_keyring_write_re_reads_before_it_applies_its_delta() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let a = hosted(store.clone());
        let b = hosted(store.clone());

        assert!(a.trust_approver_key_durable("device:phone", &pubkey(8)).unwrap());
        assert!(b.trust_approver_key_durable("device:watch", &pubkey(9)).unwrap());

        assert_eq!(
            b.approver_keyring_snapshot().trusted_key("device:phone"),
            Some(pubkey(8).as_str()),
            "B's own write must have re-read the store, so it holds A's pairing too",
        );
        let c = hosted(store.clone());
        assert_eq!(c.approver_keyring_snapshot().trusted_key("device:phone"), Some(pubkey(8).as_str()));
        assert_eq!(c.approver_keyring_snapshot().trusted_key("device:watch"), Some(pubkey(9).as_str()));
    }

    /// A WRITE IS NOT A READ. The refresh clock records when this instance last re-read the trust
    /// state; a write path that stamped it would push the staleness deadline forward without the
    /// instance ever having seen what another instance wrote. An operator toggling the floor more
    /// often than [`KEYRING_REFRESH_MS`] would then pin their instance to an indefinitely stale
    /// keyring, and a stale-empty keyring is the fail-open the whole refresh exists to close.
    #[test]
    fn writing_the_approval_floor_does_not_advance_the_keyring_refresh_clock() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store);
        let before = svc.keyring_loaded_at.load(Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(5));

        svc.set_approval_floor(Some(ApprovalFloor::DeviceSigned)).unwrap();

        assert_eq!(
            svc.keyring_loaded_at.load(Ordering::SeqCst),
            before,
            "a floor write read nothing, so it may not move the deadline for re-reading the keyring",
        );
    }

    /// A floor opt-down that did not persist used to log a warning and answer success. It never was:
    /// under `Store` persistence the next refresh reloads the stored (stricter) value straight over
    /// it, so the operator is told bearer approvals are open moments before they close again, and on
    /// a hosted worker it takes another step-up ticket to try again. It must fail loudly, and this
    /// instance must not serve the value in the meantime.
    #[test]
    fn a_floor_opt_down_that_did_not_persist_is_reported_and_rolled_back() {
        let store = Arc::new(FlakyMeta::healthy());
        let svc = hosted(store.clone() as Arc<dyn Store>);
        svc.set_approval_floor(Some(ApprovalFloor::DeviceSigned)).unwrap();
        assert_eq!(svc.approval_floor(), ApprovalFloor::DeviceSigned);

        store.writes_fail.store(true, Ordering::SeqCst);
        svc.set_approval_floor(Some(ApprovalFloor::Approve))
            .expect_err("an opt-down the store refused is not an opt-down that happened");
        assert_eq!(
            svc.approval_floor(),
            ApprovalFloor::DeviceSigned,
            "the unpersisted opt-down must be rolled back, not served until the next refresh undoes it",
        );
    }

    /// The same for the write half of a pairing: a keyring the store refused is not a keyring that
    /// changed, and the caller has to hear so: a tenant told their phone is enrolled, on a worker
    /// that forgot it, believes approvals require hardware that is not trusted.
    #[test]
    fn a_keyring_change_that_did_not_persist_is_reported() {
        let store = Arc::new(FlakyMeta::healthy());
        let svc = hosted(store.clone() as Arc<dyn Store>);
        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(10)).unwrap());

        store.writes_fail.store(true, Ordering::SeqCst);
        svc.trust_approver_key_durable("device:watch", &pubkey(11))
            .expect_err("a pairing the store refused must not be reported as enrolled");
        svc.revoke_approver_key("device:phone")
            .expect_err("a revocation the store refused comes back trusted on the next refresh");
    }

    /// The one place last-known-good is the WRONG instinct. A read is allowed to degrade to the copy
    /// this instance already holds; a write is not, because continuing would serialise a snapshot of
    /// unknown age over the shared row, which is the blind overwrite above, arrived at through a
    /// transient fault instead of a stale TTL. It must abort and leave the row alone.
    #[test]
    fn a_keyring_write_aborts_rather_than_overwriting_from_an_unverified_snapshot() {
        let store = Arc::new(FlakyMeta::healthy());
        let svc = hosted(store.clone() as Arc<dyn Store>);
        assert!(svc.trust_approver_key_durable("device:phone", &pubkey(12)).unwrap());

        store.reads_fail.store(true, Ordering::SeqCst);
        svc.revoke_approver_key("device:phone")
            .expect_err("a write that cannot verify what it is writing over must not proceed");
        assert_eq!(
            svc.approver_keyring_snapshot().trusted_key("device:phone"),
            Some(pubkey(12).as_str()),
            "an aborted mutation must not half-apply in memory either",
        );

        store.reads_fail.store(false, Ordering::SeqCst);
        let c = hosted(store.clone() as Arc<dyn Store>);
        assert_eq!(
            c.approver_keyring_snapshot().trusted_key("device:phone"),
            Some(pubkey(12).as_str()),
            "the stored row must be exactly what it was before the aborted write",
        );
    }

    #[test]
    fn a_pairing_audit_records_the_authority_and_detail_cannot_overwrite_it() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store.clone());
        svc.audit_approver_pairing(
            "allow",
            "device:phone",
            Some(&pubkey(4)),
            "owner-step-up",
            serde_json::json!({ "ticket_jti": "jti-1", "authority": "spoofed", "key_fp": "spoofed" }),
        )
        .unwrap();

        let events = store.audit_events(None).unwrap();
        let last = events.last().expect("the enrolment was recorded");
        assert_eq!(last.payload.action, "permaura.approver.pair");
        assert_eq!(last.payload.resource, "approver-keyring");
        assert_eq!(last.payload.decision, "allow");
        assert_eq!(last.payload.summary["approver_id"], "device:phone");
        assert_eq!(last.payload.summary["key_fp"], key_fingerprint(&pubkey(4)));
        assert_eq!(last.payload.summary["ticket_jti"], "jti-1");
        assert_eq!(
            last.payload.summary["authority"], "owner-step-up",
            "caller-supplied detail must not be able to rewrite who authorised the enrolment",
        );
    }

    /// An event about no particular key OMITS `key_fp` rather than writing the fingerprint of an
    /// empty string. A well-formed fingerprint that identifies nothing is indistinguishable from one
    /// that identifies a key, so a reader matching it against a ticket or a pairing notice would be
    /// comparing against a fabrication.
    #[test]
    fn an_event_about_no_particular_key_omits_the_fingerprint() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let svc = hosted(store.clone());
        svc.audit_approver_pairing(
            "deny",
            "device:never-registered",
            None,
            "operator_revocation",
            serde_json::json!({ "revoked": true, "key_fp": "smuggled" }),
        )
        .unwrap();

        let events = store.audit_events(None).unwrap();
        let last = events.last().expect("the revocation was recorded");
        assert!(
            last.payload.summary.get("key_fp").is_none(),
            "an unknown key must leave the field absent, not carry a hash of nothing: {}",
            last.payload.summary,
        );
        assert_ne!(
            last.payload.summary.get("key_fp").and_then(|v| v.as_str()),
            Some(key_fingerprint("").as_str()),
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
#[path = "session_touch_race_tests.rs"]
mod session_touch_race_tests;

#[cfg(all(test, feature = "sqlite"))]
#[path = "store_lock_tests.rs"]
mod store_lock_tests;

#[cfg(all(test, feature = "sqlite"))]
#[path = "store_lock_sibling_tests.rs"]
mod store_lock_sibling_tests;

#[cfg(test)]
#[path = "agent_gate_tests.rs"]
mod agent_gate_tests;

#[cfg(test)]
#[path = "agents_paused_tests.rs"]
mod agents_paused_tests;

#[cfg(test)]
#[path = "held_change_lock_tests.rs"]
mod held_change_lock_tests;

#[cfg(test)]
mod held_effect_budget_tests {
    use super::{effect_widened, HeldEffectRecord};
    use crate::policy_guard::{HeldEffect, Loosening, LoweredTo};

    #[test]
    fn an_unfinished_effect_comparison_requires_the_same_recorded_estate() {
        let exact = HeldEffect::Lowers(Loosening::default());
        let unknown = HeldEffect::PastBudget;
        for (then, now) in [(&exact, &unknown), (&unknown, &exact), (&unknown, &unknown)] {
            let current = HeldEffectRecord { effect: now.clone(), estate_digest: Some([1; 32]) };
            for digest in [None, Some([2; 32])] {
                let kept = HeldEffectRecord { effect: then.clone(), estate_digest: digest };
                assert!(effect_widened(Some(&kept), &current).is_some(), "a missing or changed digest retires it: {kept:?}, {current:?}");
            }
            let kept = HeldEffectRecord { effect: then.clone(), estate_digest: current.estate_digest };
            assert!(effect_widened(Some(&kept), &current).is_none(), "the unchanged estate stays confirmable");
            assert!(effect_widened(None, &current).is_some());
        }
        let kept = HeldEffectRecord { effect: exact.clone(), estate_digest: Some([1; 32]) };
        let same = HeldEffectRecord { effect: exact, estate_digest: Some([2; 32]) };
        assert!(effect_widened(Some(&kept), &same).is_none(), "known effects can be compared despite a changed estate");
        let refund = LoweredTo { principal: None, connection: "c".into(), action: "refund".into(), rung: permaura_core::Rung::Auto, quorum: 1 };
        let wider = HeldEffectRecord { effect: HeldEffect::Lowers(Loosening { named: Vec::new(), lowered: vec![refund] }), estate_digest: Some([2; 32]) };
        assert!(effect_widened(Some(&kept), &wider).is_some());
        assert!(effect_widened(None, &same).is_some(), "a pre-upgrade hold fails closed even within budget");
        assert!(effect_widened(None, &HeldEffectRecord { effect: HeldEffect::NotBinding, estate_digest: None }).is_none());
    }
}
