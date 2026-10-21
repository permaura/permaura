//! One secret, kept in the best custody this machine actually offers.
//!
//! Several secrets are resolved through here: the gateway's vault KEK that seals every stored
//! credential, the ed25519 approver key a paired device signs approvals with, and the desktop's
//! sign-in session and audience pins. The first two were macOS Keychain on macOS and a `0600` file
//! everywhere else, chosen at COMPILE time, so a Windows install got the file
//! even though Credential Manager was sitting right there, and a GNOME desktop got the file with a
//! working Secret Service behind it. The `keyring` crate always spoke all three; only the Cargo feature
//! list was mac-only.
//!
//! ## Who calls this, and why it is not in the desktop app any more
//!
//! It used to be. The desktop app minted the vault KEK, kept it in the OS credential
//! store, deleted `~/.permaura/vault-kek` once the store had it, and handed the key to the gateway it
//! spawned. The gateway had custody logic of its own (read that file, mint a fresh key when it is
//! absent) and the two never agreed. Starting `permaura start` from a terminal on a machine where
//! the app had adopted the key produced a NEW key, a gateway reporting `healthy` with
//! `audit_chain_intact: true`, and `AEAD decryption/authentication failed` on every credential the app
//! had sealed. Nothing warned.
//!
//! The app was never the right holder. It is a privileged control plane like the phone or the web
//! console, whose extras over those are installing, upgrading and starting/stopping a gateway.
//! Holding the gateway's vault key is a fourth capability that arrived by accident, and it is the one
//! that created the hand-over problem in the first place. Neither the phone nor the console holds a
//! key for the gateway it manages.
//!
//! So the gateway resolves its own key, through this module, and the app does not touch it at all.
//!
//! The first fix shipped a middle step: a one-way hand-back into the owner-only file, so a machine where
//! the app already held the key could be migrated. That ran on every launch, and once the gateway
//! could take custody for itself the two simply took turns: the app pulled the key out of the store
//! into a file, the gateway put it back, forever, writing the KEK to disk on every start. They fight
//! because they deliberately share a service and account name, so neither can tell its own entry from
//! the other's.
//!
//! **The hand-back has been deleted, not merely left uncalled.** A function that moves a secret from
//! the store back to a file is the exact shape of that bug, and the only way it recurs is somebody
//! calling it; a doc comment saying "do not" is weaker than the function not being there. Removal is
//! also what let this crate keep one honest verb: [`CredentialStore::forget`] removes a secret from
//! every custody, which is what a sign-out and an uninstall actually want. The desktop's own approver
//! key is a different secret with a different service name, and that one it legitimately owns.
//!
//! The cost of the clean break is deliberate and was accepted: a machine whose key is in the store,
//! running a gateway that cannot read it (an unsigned or pre-1.2.9 macOS build, or Linux, where the
//! gateway is static musl and Secret Service is out of reach) has no automatic migration any more. It
//! refuses to start and says how to reset. Nothing was live when that was chosen.
//!
//! ## Why the choice is made at runtime now
//!
//! Because on Linux it cannot be made any earlier. Secret Service is a D-Bus daemon: present on a
//! GNOME or KDE desktop, absent on the headless server that is the common self-host. The same binary
//! has to do the right thing on both, so it asks, and keeps the file as the floor when the answer is
//! no. macOS and Windows always answer yes.
//!
//! "Headless" here does not mean "no D-Bus", and assuming it did would get this wrong. A stock Ubuntu
//! Server has a per-user session bus at `/run/user/N/bus` the moment anyone logs in over SSH, with a
//! dozen activatable services on it: dconf, the portals, snapd. What it does not have is anything
//! providing `org.freedesktop.secrets`. That is the question worth asking, and the only one.
//!
//! Deliberately NOT `linux-native` (kernel keyutils). It needs no D-Bus, which makes it tempting for
//! exactly the headless case, but a keyutils secret lives in the session/user keyring and does not
//! survive a reboot. A vault KEK that silently disappears on restart does not fail loudly, it orphans
//! every sealed credential in the store. A file that persists is strictly better than a keyring that
//! forgets.
//!
//! ## Asking, on Linux, without asking the wrong question
//!
//! [`Custody::of`] settles it BEFORE `keyring` is touched, by talking to the session bus directly.
//! The obvious alternative (call `keyring` and read the shape of the failure) is what must not be
//! done, and the reason is the whole of the next section. `keyring` reports a locked collection as
//! `NoStorageAccess` and an unreachable bus as `PlatformFailure`, which looks like a clean split
//! until you notice `PlatformFailure` is also what a daemon that IS there but is mid-crash, or
//! answering malformed replies, or refusing on policy comes back as. Reading "no daemon" out of that
//! is reading "nothing was ever stored here" out of a machine whose vault is very much stored here.
//!
//! So the only route to [`Custody::Unavailable`] is positive proof of absence: no session bus at all,
//! or a session bus on which `org.freedesktop.secrets` is neither owned nor startable. Every other
//! answer (including every form of "I could not tell") lands on [`Custody::Native`], where a
//! subsequent failure is [`Native::Failed`] and nothing is ever minted. Being wrong in that direction
//! costs a startup error the customer can fix by unlocking their keyring. Being wrong in the other
//! costs them the vault.
//!
//! Activatable counts as present because it is the normal state of a fresh GNOME login: nothing has
//! asked for a secret yet, so `gnome-keyring-daemon` has not been started yet, and it owns the name
//! only once something does. Treating that as absence would leave a desktop install on the file
//! forever, never adopting.
//!
//! The probe and `keyring` are not the same D-Bus client, and they do not find a bus the same way:
//! zbus falls back to `$XDG_RUNTIME_DIR/bus` and then to a uid-derived `/run/user/N/bus`, while
//! libdbus honours `DBUS_SESSION_BUS_ADDRESS` and otherwise autolaunches. So the two can disagree
//! about whether a store is reachable. Neither direction is dangerous any more, because neither one
//! decides whether to mint; see the next section.
//!
//! ## What a store cannot be asked, and the marker that answers it
//!
//! The store cannot be asked whether it ever held our secret. It can only say what it holds NOW, and
//! when it is unhappy it cannot reliably say even that. Both of the useless answers, "nothing here"
//! and "I will not tell you", arrive identically on a machine whose vault key is sitting in there and
//! on a machine that has never used a keyring in its life. Those two need opposite treatment and the
//! store cannot tell them apart, so it is not asked to: [`CredentialStore::marker`] is written next to
//! the vault when a secret successfully reaches the store, and its existence is the answer.
//!
//! With it, the rule is short. The file wins whenever it still has the secret. Otherwise, an unhappy
//! store is a crisis if the marker says our secret lives in it, and a non-event if it does not.
//!
//! Both halves were found by testing rather than reasoned out, and both were wrong before:
//!
//! - Refusing on every unhappy store was unshippable. KeePassXC owns `org.freedesktop.secrets` and
//!   exposes NO usable collection until its database is open with a group explicitly exposed, so
//!   Permaura refused to start for anyone running it in that ordinary state. It is a popular password
//!   manager and that is its default.
//! - Minting whenever no store was reachable was the vault-loss bug, and it had nothing to do with
//!   locking. An install that has adopted keeps no file, so any later launch from a session with no
//!   bus saw "no store, no file", called it a first run, and re-keyed a live vault.
//!
//! One mapping inside `dbus-secret-service` is load-bearing and worth knowing about: a service with
//! no default collection comes back as `NoResult`, which `keyring` reports as `NoStorageAccess` and
//! this module reads as [`Native::Failed`]. That is what stops a closed KeePassXC being mistaken for
//! an empty store even before the marker is consulted. If a `keyring` upgrade ever routed that to
//! `NoEntry` instead, the marker would be the only thing left holding the line.
//!
//! ## The migration is the dangerous part
//!
//! An install that predates this has its secret in the file, and the native store is empty. Reading the
//! store, finding nothing, and treating that as "first run" would mint a fresh KEK and orphan the
//! customer's vault, losing every connector credential they hold. So an empty native store is never
//! conclusive on its own: the file is always consulted before anything is generated, and adoption only
//! removes the file once the value has been written to the store AND read back out of it.
//!
//! Adopting Linux fired the `Failed` and `Empty` arms on real machines for the first time (every
//! GNOME install that upgrades onto this arrives with a populated file and an empty Secret Service),
//! so the [`CredentialStore::decide`] table is the part to read before changing anything here.
//!
//! gnome-keyring raises an error on a locked collection, so it reaches `Failed` by itself, and the VM
//! run confirms it. Nothing in the spec requires that of the other implementations, and an `Empty`
//! that really means "I could not look" is handled the same way as any other unhelpful answer: by the
//! marker, not by trusting the store.
//!
//! One consequence of adoption is worth stating plainly, because it is a real edge and not a bug:
//! once an install has moved its KEK into a native store the file is gone, so launching on the SAME
//! box from a session that cannot reach the store no longer finds the secret anywhere. The marker
//! makes that a refusal with an explanation rather than a silent re-key.
//!
//! That last sentence used to end "The gateway itself is not affected; it is the desktop app that
//! holds this custody." It was wrong, and the re-keyed vault above is what it cost: the gateway was affected the moment
//! anyone started it themselves, because it had its own custody that had never heard of the marker.
//! A standalone gateway start reaches every arm of this table, and the headless case reaches them
//! with nobody present to unlock anything.
//!
//! ## Custody is only as good as the identity holding it
//!
//! A native store is not automatically an upgrade on the file. It is one when the store can tell this
//! program apart from every other program running as the same user, AND this program still looks like
//! itself after it updates. macOS is the platform where that second half is not free: Keychain ACLs
//! key on code identity, so an ad-hoc-signed binary (which is what a locally built or
//! linker-signed gateway is) gets a new identity on every build. Adopting into the Keychain from
//! one of those means a macOS authorization dialog after every single update, and on a headless box
//! it means no dialog at all and a gateway that cannot open its own vault.
//!
//! [`CredentialStore::needs_stable_code_identity`] is how a caller says it cannot survive that. The
//! desktop app does not set it: it is Developer ID signed in release, and a developer running an
//! ad-hoc build locally is sitting in front of the dialog. The gateway does set it, because it can be
//! started over SSH by systemd on a Mac mini with nobody logged in. The release pipeline signs the
//! published macOS gateway with the same Developer ID the app carries, and the app signs the copy it
//! bundles, so [`Custody::of`] answers [`Custody::Native`] for those and the gateway keeps its KEK
//! in the Keychain, through keyring's user-domain default keychain (see the section on which
//! keychain an app store uses). An ad-hoc or locally built gateway keeps it in the owner-only file.
//!
//! Windows needs none of this. Credential Manager is DPAPI-backed and per-user with no code-identity
//! ACL, so any process running as the user reads it without a prompt: no better than the owner-only
//! file against such a process, and better against an offline copy of the disk. It needs neither a
//! signature nor a probe.
//!
//! ## A fresh write, and the access list a Keychain item keeps
//!
//! A macOS Keychain item carries its own access list, naming the programs that may read it without a prompt, and a write into an item that already exists keeps that list. [`CredentialStore::store`] writes in place (keyring finds the item and modifies it), so when another program running as this user created the item first, with a list that admits itself, that program reads every value written after.
//!
//! [`CredentialStore::store_fresh`] is the write for a secret an app has just started: a new sign-in session, a new approver key, the first audience pin. It removes any item standing under the service and account, then adds the app's own through the Keychain's add, which refuses an item that is already there, so the item it leaves carries the app's access list.
//!
//! ## Which keychain an app store uses
//!
//! keyring reaches every item through the user-domain default keychain, a per-user preference that any program running as the user can repoint (`security default-keychain -d user -s`) at a keychain whose password it set. Every item written after that, the app's access list notwithstanding, is readable offline by that program. So on macOS an app store (one whose custody its operator does not set) reads, removes, writes and adds its items in the user's login keychain, named by its path under the home the user record gives, and never through the default. When the login keychain cannot be found or opened, every write fails with an error naming it (never a write to another keychain, and never the owner-only file because of it), and every read meets a store that would not answer, which with the marker standing is a refusal, never an empty store. The gateway's vault KEK keeps keyring's default keychain, as it always has.
//!
//! What a fresh write guarantees:
//!
//! - It never writes into an item it did not add. An item another program puts back between the removal and the add (or one the Keychain did not actually remove, since keyring does not report that) fails the write with [`StoreFreshError::Occupied`], is left as it is, and receives nothing. The marker is left as the write found it, since nothing can tell whose item that is.
//! - It never writes the owner-only file. An add the store refuses for any reason (an item standing, a missing login keychain, a locked or unwritable one) fails the write, so a program that makes the add fail cannot move a new session, approver key or pin into a file; one refused for a reason other than those first two then reads as an interruption at the add does. Only a routine write falls back to the file, and for an app store that does not reliably save a refresh rotation the store refused. Until the store answers a read again, [`CredentialStore::load`] returns the rotated session from a file any program running as the user can read; while its item still holds the earlier session, the first load the store answers prefers that session and removes the file, so the spent refresh token is replayed. The rotation reaches the item only through a load that finds no item it can read and then has its write of the file's value taken: one whose read the store fails, or the first one after a fresh write removed the item (below).
//! - An interruption between the removal and the add (a quit, a crash, an updater relaunch) costs only the secret being started. The marker goes before the item, so the next load reads either nothing stored (a sign-in or a pairing to do again) or, where an earlier refused routine write left the owner-only file, that write's value, which [`CredentialStore::load`] moves back into the store ([`CredentialStore::load_without_file`] never reads the file). Neither is a refusal. Nothing the user already relied on is at stake, because a fresh write is only for a value that replaces whatever stood there.
//! - On macOS the item it adds is in the login keychain, whichever keychain the user-domain default names, so repointing the default does not move the app's next secret into a keychain another program can decrypt.
//!
//! What it does not:
//!
//! - In the login keychain it cannot tell the app's item from another program's on a later read. An item planted while none of the app's stands, or re-planted after the app's own add and before a routine write, is read, and written into, as the app's own. A store kept in the data-protection keychain (below) has no such item to read.
//! - Routine writes (a refresh rotation, a later pin) stay in place. Removing the item on every write would put the only copy of a value the user relies on through the same interruption window.
//! - It does not stop a program running as the user from replacing the login keychain file itself. The data-protection keychain does, for a store kept there.
//! - It is not serialized with loads of the same store, and callers must do that themselves (a poll included). A [`CredentialStore::load`] between the removal and the add finds nothing in the store and adopts any owner-only file into a new item, which turns the fresh write into [`StoreFreshError::Occupied`].
//! - Nothing changes off macOS. Windows Credential Manager and Linux Secret Service have no per-program access list (any program running as the user reads every item), so there a fresh write is a routine one. A server's own secret ([`CredentialStore::operator_sets_custody`]) always writes in place too, and a debug build told `PERMAURA_VAULT_CUSTODY=file` writes an app store's fresh secret to the owner-only file as it does every other.
//!
//! ## The data-protection keychain
//!
//! An app store that names a keychain access group ([`CredentialStore::keychain_access_group`]) keeps its item in the data-protection keychain under that group, in a release macOS build with the `apple-data-protection` feature. Only code signed with the group in its `keychain-access-groups` entitlement can add, read, change or remove an item there, and on macOS the system launches code claiming that entitlement only under a provisioning profile Apple issued for the app, so no other program running as the user can plant an item for the app to read as its own. Every refusal there fails the read or write; nothing falls back to the login keychain or the owner-only file. The login keychain's item under the same name is never read, and the store's marker is named for the data-protection keychain, so the first load after an upgrade from the login keychain finds nothing stored: the approver key and its pin record start again, and the gateways that trusted the earlier key need this Mac paired again. A debug build is not signed into the group and keeps the login keychain.
//!
//! ## Which home an app store uses
//!
//! A store's owner-only file, its marker and the suffix on its account all follow the Permaura home, and `PERMAURA_HOME` and `HOME` are variables any program running as the user can set in the app's environment (`launchctl setenv`, `open --env`). Pointed at a directory that program chose, an app store would address an account where none of the app's items stands, find no marker, and adopt a file that program planted there as its session, approver key or pin. So on macOS a release build resolves an app store's home from the user record (`.permaura` under the home `getpwuid` gives, the account unsuffixed), whatever the environment says. A debug build, and this crate's own unit tests in any profile, keep honoring `PERMAURA_HOME`, so a developer and a test harness can still isolate a home. An integration test links the library without `cfg(test)`, so in a release Keychain build an app store there resolves the user's real home whatever the test sets, and the test has to guard itself, as the real store round trip (`tests/real_store.rs`) does: it fails before touching any store unless its store resolves under its scratch `PERMAURA_HOME`. The gateway's vault KEK keeps taking its home from the environment, and Windows and Linux are unchanged: there any program running as the user already reads and writes every item, so a home it relocates gives it nothing.

// `deny` rather than `forbid`, for exactly one exception: [`owner_only`], where a protected Windows
// DACL means `SetNamedSecurityInfoW` and there is no safe wrapper for it. Everything else in this
// crate is still refused unsafe at compile time, and `permaura-core` still forbids it outright.
#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use keyring::Entry;

/// Opens the OS-store entry for an account, passed in so a test can hand the read and write paths a store of its own rather than this machine's.
type OpenEntry<'a> = &'a dyn Fn(&str) -> Result<Entry, String>;

/// Adds a secret as a new item under an opened entry, refusing one that already stands, for a store whose items carry their own access list; passed in for the reason [`OpenEntry`] is.
type AddOwnItem<'a> = &'a dyn Fn(&Entry, &str) -> Result<(), AddRefused>;

/// Why the store did not add an item of this program's own.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(all(target_os = "macos", feature = "apple-native")), allow(dead_code))]
enum AddRefused {
    /// An item already stands under the service and account.
    Occupied,
    /// The login keychain could not be found or opened.
    NoLoginKeychain(NoLoginKeychain),
    /// The store refused the add for another reason: locked, denied, broken.
    Failed(String),
}

/// The login keychain an app store addresses on macOS could not be found or opened; it travels inside a keyring error so every path that meets it refuses rather than falling back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(all(target_os = "macos", feature = "apple-native")), allow(dead_code))]
struct NoLoginKeychain(String);

impl std::fmt::Display for NoLoginKeychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the login keychain could not be used ({})", self.0)
    }
}

impl std::error::Error for NoLoginKeychain {}

impl From<NoLoginKeychain> for keyring::Error {
    fn from(e: NoLoginKeychain) -> Self {
        keyring::Error::NoStorageAccess(Box::new(e))
    }
}

/// The missing login keychain behind a store error, if that is what it was.
fn missing_login_keychain(e: &keyring::Error) -> Option<&NoLoginKeychain> {
    match e {
        keyring::Error::NoStorageAccess(inner) => inner.downcast_ref::<NoLoginKeychain>(),
        _ => None,
    }
}

/// The data-protection keychain refused a read, write or removal; it travels inside a keyring error so a write meeting it refuses rather than falling back to the owner-only file, which nothing reads for a store kept there.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(all(target_os = "macos", feature = "apple-data-protection")), allow(dead_code))]
struct DataProtectionRefused(String);

impl std::fmt::Display for DataProtectionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the data-protection keychain refused it ({})", self.0)
    }
}

impl std::error::Error for DataProtectionRefused {}

impl From<DataProtectionRefused> for keyring::Error {
    fn from(e: DataProtectionRefused) -> Self {
        keyring::Error::NoStorageAccess(Box::new(e))
    }
}

/// The data-protection keychain's refusal behind a store error, if that is what it was.
fn data_protection_refusal(e: &keyring::Error) -> Option<&DataProtectionRefused> {
    match e {
        keyring::Error::NoStorageAccess(inner) => inner.downcast_ref::<DataProtectionRefused>(),
        _ => None,
    }
}

/// Why a fresh write failed, so a caller can tell the refusal it has to act on from the rest; each carries the text [`CredentialStore::store_fresh`] returns, and `String::from` gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreFreshError {
    /// An item still stood under the service and account when the app added its own, and nothing was written into it. It is the app's own item whose removal did not take, or one another program put back, and nothing can tell which: never retry with [`CredentialStore::store`], which writes into the item it finds, and do not read the store as holding the app's secret until a fresh write succeeds ([`CredentialStore::forget`] removes the item).
    Occupied(String),
    /// The login keychain could not be found or opened, so nothing was written to it, to any other keychain or to the owner-only file.
    LoginKeychainUnavailable(String),
    /// Anything else that stopped the write: the entry could not be opened, the standing item or the marker could not be removed, the store refused the add (locked, denied, unwritable), or the owner-only file a routine write lands in could not be written. An app store's fresh write into the macOS Keychain writes nothing to that file. Every other fresh write (a server's own store, a build off the Keychain, a debug build told `PERMAURA_VAULT_CUSTODY=file`) is a routine one, and its file can already be in place when it fails (on Windows, when the file's owner-only access list cannot be set).
    Failed(String),
}

impl StoreFreshError {
    /// The text a person reads.
    pub fn message(&self) -> &str {
        match self {
            Self::Occupied(m) | Self::LoginKeychainUnavailable(m) | Self::Failed(m) => m,
        }
    }
}

impl std::fmt::Display for StoreFreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for StoreFreshError {}

impl From<StoreFreshError> for String {
    fn from(e: StoreFreshError) -> Self {
        match e {
            StoreFreshError::Occupied(m) | StoreFreshError::LoginKeychainUnavailable(m) | StoreFreshError::Failed(m) => m,
        }
    }
}

/// The add a fresh write makes in this build: the Keychain's own.
#[cfg(all(target_os = "macos", feature = "apple-native"))]
fn own_item_add() -> Option<AddOwnItem<'static>> {
    Some(&add_keychain_item)
}

/// `None`: no store this build reaches gives an item an access list of its own, so a fresh write is a routine one.
#[cfg(not(all(target_os = "macos", feature = "apple-native")))]
fn own_item_add() -> Option<AddOwnItem<'static>> {
    None
}

/// The Keychain's add for `entry`, in the login keychain: the call keyring's own write makes when it finds no item, so the item gets the same default access list, without keyring's find-then-modify when it does. Only an app store's entry is a login keychain item, and only an app store makes a fresh write of its own.
#[cfg(all(target_os = "macos", feature = "apple-native"))]
fn add_keychain_item(entry: &Entry, secret: &str) -> Result<(), AddRefused> {
    #[cfg(feature = "apple-data-protection")]
    if let Some(item) = entry.get_credential().downcast_ref::<data_protection::DataProtectionItem>() {
        return item.add(secret);
    }
    match entry.get_credential().downcast_ref::<login_keychain::LoginKeychainItem>() {
        Some(item) => item.add(secret),
        None => Err(AddRefused::Failed("the entry is not a login keychain item".into())),
    }
}

/// What a refused Keychain add means to a fresh write.
#[cfg(all(target_os = "macos", feature = "apple-native"))]
fn keychain_add_refusal(e: security_framework::base::Error) -> AddRefused {
    /// errSecDuplicateItem, from SecBase.h.
    const DUPLICATE_ITEM: i32 = -25299;
    if e.code() == DUPLICATE_ITEM {
        AddRefused::Occupied
    } else if login_keychain::names_no_keychain(&e) {
        AddRefused::NoLoginKeychain(NoLoginKeychain(e.to_string()))
    } else {
        AddRefused::Failed(e.to_string())
    }
}

#[cfg(all(target_os = "macos", feature = "apple-data-protection"))]
mod data_protection;
#[cfg(all(target_os = "macos", feature = "apple-native"))]
mod login_keychain;
mod owner_only;
pub use owner_only::restrict_to_owner;

/// Whether this build has a REAL OS credential store behind `keyring`.
///
/// This has to be asked explicitly, and it is the single most dangerous line in the module. On a
/// platform with no backend feature compiled in, `keyring` silently resolves to its in-memory `mock`
/// store, which answers `NoEntry` when read (harmless) and returns `Ok(())` from a WRITE that goes
/// nowhere and is gone at exit. Trusting that write would mean never falling back to the file, and a
/// vault KEK that exists only until the process ends: every sealed credential orphaned on restart,
/// with nothing having reported an error.
///
/// It used to be a hand-maintained platform list that had to be remembered alongside the `keyring`
/// feature list, with a comment saying so. It is now DERIVED from that feature list, so the two
/// cannot drift: each arm names the platform and the feature that provides a backend for it. The
/// feature without the constant left a working store unused; the constant without the feature handed
/// the mock a vault KEK and lost it at exit. Neither is reachable now.
///
/// Note what this does NOT say: that a store is reachable, or that this binary may safely hold
/// something in it. Those are [`Custody::of`]'s questions, asked per launch.
const HAS_NATIVE_STORE: bool = (cfg!(target_os = "macos") && cfg!(feature = "apple-native"))
    || (cfg!(target_os = "windows") && cfg!(feature = "windows-native"))
    || (cfg!(target_os = "linux")
        && (cfg!(feature = "linux-sync-secret-service")
            || cfg!(feature = "linux-async-secret-service")));

/// Whether this process has a code identity that will still be the same one after it updates.
///
/// Only macOS asks. Keychain ACLs are recorded against the requesting code's designated requirement,
/// so the question is whether we have a certificate-based identity (Developer ID) rather than an
/// ad-hoc/linker-signed one whose identity is its build hash. Every ambiguity answers `false`: being
/// wrong that way costs an owner-only file instead of a keychain item, while being wrong the other
/// way costs an authorization dialog on every update and a headless install that cannot open its own
/// vault at all.
///
/// The requirement deliberately does not name a team. The property that matters is "issued by Apple
/// as a Developer ID Application certificate", which is what makes the identity survive an update;
/// pinning our own team on top would add nothing and would make a fork's build silently take the
/// weaker path. `field.1.2.840.113635.100.6.1.13` is Apple's Developer ID Application marker OID.
#[cfg(all(target_os = "macos", feature = "apple-native"))]
fn stable_code_identity() -> bool {
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

    const DEVELOPER_ID: &str =
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";

    let Ok(requirement) = DEVELOPER_ID.parse::<SecRequirement>() else { return false };
    let Ok(me) = SecCode::for_self(Flags::NONE) else { return false };
    me.check_validity(Flags::NONE, &requirement).is_ok()
}

/// Everywhere else the question does not arise: Windows Credential Manager and Secret Service do not
/// gate reads on the caller's code identity, so there is no identity to keep stable.
#[cfg(not(all(target_os = "macos", feature = "apple-native")))]
fn stable_code_identity() -> bool {
    true
}

/// What custody this machine offers, answered at launch rather than at compile time.
///
/// Split from `HAS_NATIVE_STORE` because on Linux the two genuinely differ: the store is compiled in
/// and may still be unreachable. Passed explicitly into everything that reads or writes so the tests
/// can drive an arm this machine could not otherwise produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Custody {
    /// A real OS credential store, reachable now. Read it, write it, adopt into it.
    Native,
    /// Nothing compiled in for this platform. The file is the custody, permanently.
    NoStore,
    /// A store is compiled in, and this launch cannot safely use it. Two ways to get here, and they
    /// are the same conclusion: a headless Linux box with no session bus (or a session bus with no
    /// Secret Service provider on it), or a macOS binary with no stable code identity, which may read
    /// the Keychain today but not after it updates. The file is the custody for this launch; another
    /// launch on the same install (a desktop session, a signed build) would answer `Native`.
    #[cfg_attr(
        not(any(target_os = "linux", all(target_os = "macos", feature = "apple-native"))),
        allow(dead_code)
    )]
    Unavailable(&'static str),
}

impl Custody {
    /// The answer for this launch, for a caller with these needs.
    ///
    /// `needs_stable_code_identity` is the caller saying it cannot live with a store that will stop
    /// recognising it after an update. See [`CredentialStore::needs_stable_code_identity`]. It is
    /// asked before the Linux probe only because it is the cheaper of the two.
    ///
    /// `file_requested` is the operator's `PERMAURA_VAULT_CUSTODY=file`, already narrowed by [`CredentialStore::custody`] to the stores and builds allowed to honor it.
    fn of(needs_stable_code_identity: bool, file_requested: bool) -> Self {
        // FIRST, above every probe: an explicit "keep it in the file" from the operator. Everything
        // below answers what this machine CAN do, and that is a different question from what it
        // should do, so a capability answer must not pre-empt an instruction.
        //
        // It was below `HAS_NATIVE_STORE` to begin with, which read fine and was wrong: on a build
        // with no store compiled in the operator's setting was never even looked at, and the answer
        // came back "this build has no OS credential store" for an install that had asked for the
        // file by name. Same custody either way, so nothing was mis-stored, but the reason a person
        // reads in a refusal was about the build rather than about their own configuration.
        //
        // Two cases need this. A signed gateway on a headless Mac adopts in a GUI session and then
        // cannot read the login keychain over SSH or from a launchd daemon, and by then the file is
        // gone; setting this BEFORE the first adoption is what prevents that, since afterwards there
        // is nothing to recover. And a test harness needs a home it can genuinely isolate.
        if file_requested {
            return Custody::Unavailable("this install is configured to keep its secrets in a file");
        }
        if !HAS_NATIVE_STORE {
            return Custody::NoStore;
        }
        if needs_stable_code_identity && !stable_code_identity() {
            log::info!(
                "permaura: this build has no Developer ID signature, so a keychain item it created \
                 would stop being readable without a prompt the next time it updates; secrets stay in \
                 the owner-only file"
            );
            return Custody::Unavailable(
                "this build is not signed with a Developer ID, so it does not use the OS credential store",
            );
        }
        #[cfg(all(
            target_os = "linux",
            any(feature = "linux-sync-secret-service", feature = "linux-async-secret-service")
        ))]
        if !secret_service_present() {
            return Custody::Unavailable("this session has no Secret Service to reach");
        }
        Custody::Native
    }

    /// Whether the OS store is worth writing to. The file is the fallback for the other two.
    fn is_native(self) -> bool {
        matches!(self, Custody::Native)
    }
}

/// Whether this session can actually reach a Secret Service provider.
///
/// Answers only from evidence, and every ambiguity resolves to `true`. See the module comment for
/// why that asymmetry is the point rather than laziness. `false` requires either no session bus or a
/// session bus that positively does not know the name.
///
/// Cheap enough to run at every launch: two method calls on the bus, no I/O beyond the socket.
#[cfg(all(
    target_os = "linux",
    any(feature = "linux-sync-secret-service", feature = "linux-async-secret-service")
))]
fn secret_service_present() -> bool {
    /// The well-known name every Secret Service provider claims: gnome-keyring, kwallet, KeePassXC.
    const SECRETS: &str = "org.freedesktop.secrets";

    // No session bus is the headless server, and it is the one unambiguous no: Secret Service IS a
    // D-Bus protocol, so with no bus there is nothing that could be holding a secret.
    let Ok(conn) = zbus::blocking::Connection::session() else {
        log::info!(
            "permaura: no D-Bus session bus, so no Secret Service; secrets stay in the owner-only file"
        );
        return false;
    };
    let Ok(dbus) = zbus::blocking::fdo::DBusProxy::new(&conn) else {
        return true;
    };
    let name: zbus::names::BusName = SECRETS.try_into().expect("valid bus name");
    if dbus.name_has_owner(name).unwrap_or(true) {
        return true;
    }
    // Nobody owns it yet, which on a fresh desktop login is normal: gnome-keyring-daemon starts on
    // first use. Startable is present.
    match dbus.list_activatable_names() {
        Ok(names) => {
            let startable = names.iter().any(|n| n.as_str() == SECRETS);
            if !startable {
                log::info!(
                    "permaura: a session bus is present but nothing provides {SECRETS}; secrets stay \
                     in the owner-only file"
                );
            }
            startable
        }
        Err(_) => true,
    }
}

/// What to call this machine's credential store in text a person reads.
///
/// Lives here because this module is what decides which store is in use, and the alternative is the
/// string drifting away from the choice, which is exactly what happened: the KEK failure alert told
/// every platform to open Keychain Access, including Windows, from the day Credential Manager was
/// adopted.
///
/// Only ever shown on the [`Native::Failed`] path, which means a store this machine really does have.
/// A headless Linux box is [`Custody::Unavailable`] and never reaches any of this.
pub fn store_display_name() -> &'static str {
    if cfg!(all(target_os = "macos", feature = "apple-native")) {
        "the macOS Keychain"
    } else if cfg!(all(target_os = "windows", feature = "windows-native")) {
        "Windows Credential Manager"
    } else {
        "your desktop keyring"
    }
}

/// The one thing a person can actually do about a store that will not open. Paired with
/// [`store_display_name`] so the app never names one store and the fix for another.
pub fn store_unlock_hint() -> &'static str {
    if cfg!(all(target_os = "macos", feature = "apple-native")) {
        "open Keychain Access and confirm your login keychain is unlocked"
    } else if cfg!(all(target_os = "windows", feature = "windows-native")) {
        "sign out and back in to Windows, which reopens Credential Manager for your account"
    } else {
        "unlock your login keyring: on GNOME that is Passwords and Keys (seahorse), on KDE it is KWallet"
    }
}

/// A fresh 256-bit secret as unpadded base64: ASCII, no `=`, no whitespace, safe to put in a file,
/// an environment block or a keychain item without escaping.
///
/// The encoding is load-bearing only in that it must never change for an EXISTING secret: what is
/// stored is read back verbatim, so a value minted years ago in a different alphabet keeps working.
/// This is what new ones look like.
pub fn generate_secret() -> String {
    use base64::Engine as _;
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("OS RNG must be available to generate a secret");
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(buf)
}

/// Whether the operator has asked for file custody outright.
///
/// Read from the environment because that is what `config.toml` populates before anything else runs
/// (see the gateway's `config::load_and_apply`), so one reader serves both the file and a deployment
/// that sets the variable directly.
fn truthy_file_custody() -> bool {
    std::env::var("PERMAURA_VAULT_CUSTODY")
        .map(|v| v.trim().eq_ignore_ascii_case("file"))
        .unwrap_or(false)
}

/// What to do about a refusal from the data-protection keychain, which a correctly signed app meets only when the keychain itself fails.
const DATA_PROTECTION_REMEDY: &str = "Install the app again from its official download, which is signed to use its own keychain, then try again.";

/// Whether every store honors the environment's custody settings rather than only a server's: a debug build, so a developer and a test harness can still isolate a home.
const DEBUG_BUILD: bool = cfg!(debug_assertions);

/// Whether an app store takes its home from `PERMAURA_HOME` and `HOME` rather than the user record: a debug build, so a developer and a dependent crate's debug tests can still isolate one, and this crate's own unit tests in any profile, so none of them resolves the user's real home. An integration test links the library without `cfg(test)`, so in a release Keychain build it gets the user record's home and has to guard itself, as `tests/real_store.rs` does.
const APP_HOME_FROM_ENV: bool = cfg!(any(test, debug_assertions));

/// Whether this build ever keeps an app store's home in the user record: the macOS Keychain build, whose items an app store owns by access list. Elsewhere any program running as the user already reads and writes every item, so a home it relocates gives it nothing.
const APP_HOME_IN_USER_RECORD: bool = cfg!(all(target_os = "macos", feature = "apple-native"));

/// Whether this build can keep an app store in the data-protection keychain: macOS, with the feature only an app signed into its access group turns on.
const HAS_DATA_PROTECTION: bool = cfg!(all(target_os = "macos", feature = "apple-data-protection"));

/// The Permaura home under the home the user record gives.
#[cfg(all(target_os = "macos", feature = "apple-native"))]
fn user_record_permaura_home() -> Result<std::path::PathBuf, String> {
    login_keychain::user_record_home().map(|home| home.join(".permaura"))
}

/// Never reached: off the Keychain build every store's home comes from the environment.
#[cfg(not(all(target_os = "macos", feature = "apple-native")))]
fn user_record_permaura_home() -> Result<std::path::PathBuf, String> {
    Err("this build keeps no store's home in the user record".into())
}

static IGNORED_VAULT_CUSTODY: AtomicBool = AtomicBool::new(false);
static IGNORED_CREDENTIALS_DIRECTORY: AtomicBool = AtomicBool::new(false);
static RETIRE_FAILURE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Log that `name` is set and ignored, the first time `reported` is seen unset; true when it logged.
fn report_ignored(name: &str, reported: &AtomicBool) -> bool {
    if reported.swap(true, Ordering::Relaxed) {
        return false;
    }
    log::warn!("{}", ignored_override_warning(name));
    true
}

/// The one warning a process logs for `name`, whichever store reads it first, so it speaks for every app store.
fn ignored_override_warning(name: &str) -> String {
    format!(
        "permaura: {name} is set and ignored by every app credential store in this process; a shipped \
         build does not let the environment choose where an app's secrets are kept, and only a server's \
         own store takes its custody from the environment"
    )
}

/// A short digest of the Permaura home when it is NOT the default one, or `None` when it is.
///
/// `None` is the answer that matters: it is what keeps every ordinary install addressing the exact
/// account name it always has. Only a deliberately relocated home gets a suffix, and it is derived
/// from the resolved path rather than the raw variable so that pointing `PERMAURA_HOME` at the default
/// location is still the default.
///
/// Eight hex characters is plenty. This separates installs on one machine, it is not a security
/// boundary, and a collision costs two custom-home installs a shared entry, which is exactly what they
/// have today.
fn scoped_home_suffix() -> Option<String> {
    let home = permaura_core::permaura_home()?;
    let default = dirs_default_home();
    if default.as_deref() == Some(home.as_path()) {
        return None;
    }
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(home.to_string_lossy().as_bytes());
    Some(digest.iter().take(4).map(|b| format!("{b:02x}")).collect())
}

/// The home Permaura would use with no override, so "is this the default?" is a path comparison rather
/// than an environment one.
fn dirs_default_home() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .filter(|h| !h.as_os_str().is_empty())
        .map(|h| h.join(".permaura"))
}

/// Where one secret lives, in both custodies.
pub struct CredentialStore {
    /// Keychain / Credential Manager / Secret Service service name. Stable forever: changing it
    /// orphans the existing secret.
    pub service: &'static str,
    /// The account within that service. Also stable forever.
    pub account: &'static str,
    /// The pre-native file under the Permaura home, still the fallback where no store is available.
    pub file_name: &'static str,
    /// Whether this caller needs the native store to keep recognising it after it updates itself.
    ///
    /// Set it when a failed read cannot be answered by a person: a background service, anything that
    /// may run over SSH or from `launchd`/systemd with no session to draw a dialog on. Where it is
    /// set and this build cannot prove a certificate-based code identity, the file is used instead of
    /// the native store. See the module docs. It changes nothing off macOS, where no store gates
    /// reads on who is asking.
    ///
    /// Leave it false for an attended GUI program: it is signed in release, and a developer running
    /// an unsigned local build is present to approve the dialog.
    pub needs_stable_code_identity: bool,
    /// Whether a release build lets the environment choose this secret's custody, through `PERMAURA_VAULT_CUSTODY=file` and systemd's `CREDENTIALS_DIRECTORY`, and on macOS its home, through `PERMAURA_HOME` and `HOME`; a debug build honors all of them for every store.
    ///
    /// Set it only for a server's own secret whose operator configures it that way, which is the gateway's vault KEK. Leave it false for an app's store: any process running as the user can set an app's environment (`launchctl setenv`, `open --env`), and the next sign-in then wrote the desktop's refresh token to a plaintext file, or the next load adopted a file planted under a home that process chose.
    pub operator_sets_custody: bool,
    /// The keychain access group an app store keeps its item under in the data-protection keychain, or `None` for the login keychain.
    ///
    /// Only an app store, in a release build with the `apple-data-protection` feature on macOS, reads it; everywhere else it changes nothing. The build has to be signed with the group in its `keychain-access-groups` entitlement, which on macOS needs an embedded provisioning profile: one without it gets a refusal from every read and write, never a fallback to the login keychain or the owner-only file. An item the login keychain holds under the same service and account is not read, and the store's marker has a name of its own, so a claim the login keychain's item left behind does not turn a first load here into a refusal.
    pub keychain_access_group: Option<&'static str>,
}

/// What the OS credential store had to say. Three different kinds of "no", and they are not
/// interchangeable: conflating them is how a live vault gets re-keyed.
enum Native {
    /// The secret, from the store.
    Found(String),
    /// A working store that has never been written to. On an upgraded install the file may still hold
    /// the secret, and if it does not, this really is first run.
    Empty,
    /// No store is compiled in for this platform at all. The file is the custody, and an empty file
    /// really is first run.
    NoStore,
    /// A store is compiled in and this launch cannot use it: the headless Linux case, or a macOS
    /// build with no stable code identity. Same conclusion as `NoStore` and deliberately NOT the same
    /// as `Failed`: we did not fail to read a store, we established there is no store to read from
    /// here, so an empty file really is first run.
    ///
    /// Carries the reason because the two causes need different things done about them, and the one
    /// place this text is ever read is a refusal telling somebody how to get their vault back.
    /// Reached only from [`Custody::Unavailable`], which takes positive proof either way. A locked
    /// keyring is a store that exists, so it lands on `Failed`.
    Unavailable(&'static str),
    /// A store that exists and refused to answer: locked, denied, broken. We learned NOTHING, so an
    /// empty file here means "unknown", never "first run".
    Failed(String),
}

/// Which custody answered, so the caller can decide whether a migration is owed.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    /// A credential systemd placed in `$CREDENTIALS_DIRECTORY` for this unit.
    ///
    /// Read-only from here by design: systemd owns the plaintext for the lifetime of the unit, at
    /// `0400` for the service user. Whether the form on disk is encrypted, and whether it is sealed
    /// to the TPM, depends on how the operator provisioned it, which this crate cannot tell. Nothing
    /// in this crate writes it, so there is no adoption and no minting when one is present.
    SystemdCredential(String),
    /// Already in the OS credential store. Nothing to do.
    Native(String),
    /// Only in the file: an install that predates native custody, or a machine with no store.
    File(String),
    /// Neither. The only answer that may lead to minting a fresh secret.
    Absent,
}

/// Whether a load asks the owner-only file, and so may adopt it into a store that holds nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileRead {
    /// [`CredentialStore::load`]'s: the file is asked whenever the store does not return the secret, and compared with what it does return.
    Asked,
    /// [`CredentialStore::load_without_file`]'s: the file is treated as absent, never read, compared or adopted.
    Skipped,
}

impl CredentialStore {
    /// Whether this store takes its custody from the environment in a build of this kind.
    fn custody_from_env(&self, debug_build: bool) -> bool {
        self.operator_sets_custody || debug_build
    }

    /// The custody for this launch; a file request this store may not honor is reported once per process and leaves the platform store's answer in place.
    fn custody(&self, debug_build: bool, reported: &AtomicBool) -> Custody {
        let mut file_requested = truthy_file_custody();
        if file_requested && !self.custody_from_env(debug_build) {
            report_ignored("PERMAURA_VAULT_CUSTODY", reported);
            file_requested = false;
        }
        Custody::of(self.needs_stable_code_identity, file_requested)
    }

    /// The account this install addresses in the OS store.
    ///
    /// A file is scoped by `PERMAURA_HOME`; an OS-store entry is not. It is addressed by a fixed
    /// service/account pair, so two installs with different homes on one machine reach for the SAME
    /// entry: the first to adopt puts its key there, the second finds it, and both then seal separate
    /// vaults under one key. Nothing warns, and removing either install's entry takes the other's key
    /// with it. That is the same class of defect as the re-keyed vault in the module docs, arrived at from the other side.
    ///
    /// So a home that is not the default gets its own account, suffixed with a short digest of the
    /// resolved home path. The DEFAULT home keeps the bare name it has always used, because changing
    /// it would orphan every existing install, and the comparison is between resolved paths rather
    /// than "is the variable set" so that `PERMAURA_HOME=~/.permaura` is still the default.
    ///
    /// This is also what lets a test isolate itself: a scratch home now gets a scratch entry, so a
    /// harness can build the "sealed under a key this store does not have" state that reproducing the re-keyed vault
    /// needs, which on a signed macOS build it otherwise cannot.
    ///
    /// An app store whose home comes from the user record (see [`Self::home_in`]) is at the default home by construction, so it keeps the bare name whatever the environment says.
    fn account_for_home(&self) -> String {
        self.account_in(APP_HOME_FROM_ENV)
    }

    /// [`Self::account_for_home`] for a build of this kind.
    fn account_in(&self, home_from_env_build: bool) -> String {
        match self.home_suffix(home_from_env_build) {
            Some(suffix) => format!("{}@{suffix}", self.account),
            None => self.account.to_string(),
        }
    }

    /// The suffix a relocated home gives this store's account, and never one for a home from the user record.
    fn home_suffix(&self, home_from_env_build: bool) -> Option<String> {
        if !self.home_from_env(home_from_env_build) {
            return None;
        }
        scoped_home_suffix()
    }

    /// Whether this store takes its home from the environment in a build of this kind: always for a server's own store, and for an app store only in a debug build or off the Keychain build.
    fn home_from_env(&self, home_from_env_build: bool) -> bool {
        self.operator_sets_custody || home_from_env_build || !APP_HOME_IN_USER_RECORD
    }

    /// The Permaura home this store's file and marker live under.
    ///
    /// Any program running as the user can set `PERMAURA_HOME` and `HOME` in the app's environment (`launchctl setenv`, `open --env`). Pointed at a directory it chose, an app store would address an account where nothing of the app's stands, find no marker there, and adopt a file that program planted, so a release Keychain build resolves an app store's home from the user record instead.
    fn home_in(&self, home_from_env_build: bool) -> Result<std::path::PathBuf, String> {
        if self.home_from_env(home_from_env_build) {
            return permaura_core::permaura_home()
                .ok_or_else(|| format!("could not resolve the Permaura home directory for {}", self.account));
        }
        user_record_permaura_home()
            .map_err(|why| format!("could not resolve the Permaura home directory for {} ({why})", self.account))
    }

    /// The OS-store entry for `account`: on macOS an app store's is in the data-protection keychain when it names an access group and the login keychain otherwise (see the module docs), and a server's own store keeps keyring's default keychain.
    fn entry_named(&self, account: &str) -> Result<Entry, String> {
        self.entry_in(account, DEBUG_BUILD)
    }

    /// [`Self::entry_named`] for a build of this kind.
    fn entry_in(&self, account: &str, debug_build: bool) -> Result<Entry, String> {
        #[cfg(all(target_os = "macos", feature = "apple-data-protection"))]
        if let Some(group) = self.data_protection_in(debug_build) {
            return data_protection::DataProtectionItem::new(self.service, account, group)
                .map(|item| Entry::new_with_credential(Box::new(item)))
                .map_err(|e| format!("opening the credential store entry for {account} failed: {e}"));
        }
        #[cfg(not(all(target_os = "macos", feature = "apple-data-protection")))]
        let _ = debug_build;
        #[cfg(all(target_os = "macos", feature = "apple-native"))]
        if !self.operator_sets_custody {
            return login_keychain::LoginKeychainItem::new(self.service, account)
                .map(|item| Entry::new_with_credential(Box::new(item)))
                .map_err(|e| format!("opening the credential store entry for {account} failed: {e}"));
        }
        Entry::new(self.service, account).map_err(|e| {
            format!("opening the credential store entry for {account} failed: {e}")
        })
    }

    /// The account this install used before homes were scoped, or `None` when there is no reason to
    /// look there.
    ///
    /// Gated on this home's own marker, and that gate is load-bearing in both directions. Without it
    /// the fallback would hand a relocated home the DEFAULT install's key the moment it looked, which
    /// is the collision this scoping exists to end, just reached through the back door. With it, the
    /// only home that reads the old name is one whose own marker says it adopted something, which is
    /// exactly the install that would otherwise be told its key had vanished.
    fn legacy_account(&self) -> Option<String> {
        self.home_suffix(APP_HOME_FROM_ENV)?;
        let marker = self.marker().ok()?;
        marker.exists().then(|| self.account.to_string())
    }

    /// The marker recording that this secret has been successfully written to the OS store, and that
    /// the store is therefore where it lives.
    ///
    /// Not a secret, and never read for its contents: only its existence is the claim. It answers the
    /// one question the store itself cannot be trusted to answer when it is unhappy ("was anything of
    /// mine ever put in there?") and that is what separates a machine that may be about to lose its
    /// vault from a machine that has simply never used a keyring.
    ///
    /// It sits in the Permaura home beside `gateway.db`, deliberately. Losing the marker while keeping
    /// the vault would be the one way this could mislead, and the two share a directory: whatever
    /// deletes the marker has deleted the sealed store it was protecting, so minting afterwards costs
    /// nothing.
    pub fn marker(&self) -> Result<std::path::PathBuf, String> {
        self.marker_for(APP_HOME_FROM_ENV, DEBUG_BUILD)
    }

    /// [`Self::marker`] for a build of this kind.
    #[cfg(test)]
    fn marker_in(&self, home_from_env_build: bool) -> Result<std::path::PathBuf, String> {
        self.marker_for(home_from_env_build, home_from_env_build)
    }

    /// [`Self::marker`] for a build of this kind, named for the keychain the store keeps its item in: the login keychain's claim says nothing about the data-protection keychain, where an earlier build never wrote.
    fn marker_for(&self, home_from_env_build: bool, debug_build: bool) -> Result<std::path::PathBuf, String> {
        let claim = if self.data_protection_in(debug_build).is_some() { "in-data-protection-keychain" } else { "in-os-store" };
        Ok(self.path_in(home_from_env_build)?.with_file_name(format!("{}.{claim}", self.file_name)))
    }

    /// The access group this store keeps its item under in the data-protection keychain in a build of this kind: an app store's own, in a release build that has the keychain, and `None` everywhere else.
    fn data_protection_in(&self, debug_build: bool) -> Option<&'static str> {
        if !HAS_DATA_PROTECTION || self.operator_sets_custody || debug_build {
            return None;
        }
        self.keychain_access_group
    }

    /// The keychain this store's writes name in a refusal.
    fn keychain_name(&self) -> &'static str {
        if self.data_protection_in(DEBUG_BUILD).is_some() {
            "data-protection keychain"
        } else {
            "login keychain"
        }
    }

    /// The fallback file under the Permaura home. Public alongside [`CredentialStore::marker`] so a
    /// caller that has to REPORT what it removed can name the two paths without re-deriving the
    /// marker's suffix, which is the kind of duplication that drifts.
    ///
    /// On macOS a release build puts an app store's file under the home the user record gives, whatever `PERMAURA_HOME` and `HOME` say (see [`Self::home_in`]).
    pub fn path(&self) -> Result<std::path::PathBuf, String> {
        self.path_in(APP_HOME_FROM_ENV)
    }

    /// [`Self::path`] for a build of this kind.
    fn path_in(&self, home_from_env_build: bool) -> Result<std::path::PathBuf, String> {
        Ok(self.home_in(home_from_env_build)?.join(self.file_name))
    }

    fn load_native(&self, custody: Custody, open: OpenEntry) -> Native {
        match custody {
            Custody::NoStore => return Native::NoStore,
            Custody::Unavailable(why) => return Native::Unavailable(why),
            Custody::Native => {}
        }
        let entry = match open(&self.account_for_home()) {
            Ok(e) => e,
            Err(e) => return Native::Failed(e),
        };
        match entry.get_password() {
            Ok(secret) => Native::Found(secret),
            // Nothing under this install's own account. Before calling that empty, ask the account a
            // custom-home install used before homes were scoped: reporting "first run" to someone
            // whose key is sitting under the old name is the mint-over-a-live-vault move.
            Err(keyring::Error::NoEntry) => match self.legacy_account() {
                None => Native::Empty,
                Some(legacy) => match open(&legacy).and_then(|e| {
                    e.get_password().map_err(|e| e.to_string())
                }) {
                    Ok(secret) => {
                        log::info!(
                            "permaura: {} was found under the pre-scoping account name; this install \
                             will keep using it until it is next written",
                            self.account
                        );
                        Native::Found(secret)
                    }
                    Err(_) => Native::Empty,
                },
            },
            Err(e) => Native::Failed(e.to_string()),
        }
    }

    fn load_file(path: &Path) -> Result<Option<String>, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(Some(s.trim_end_matches(['\n', '\r']).to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("reading {} failed: {e}", path.display())),
        }
    }

    /// Record that the OS store holds this secret. Best effort at the call sites that can survive
    /// failing, load-bearing at the one that cannot (see [`CredentialStore::adopt_from_file`]).
    fn claim_for_store(marker: &Path) -> Result<(), String> {
        if let Some(dir) = marker.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("creating {} failed: {e}", dir.display()))?;
        }
        std::fs::write(marker, "the secret with this name lives in this machine's OS credential store\n")
            .map_err(|e| format!("writing {} failed: {e}", marker.display()))
    }

    /// Write the secret to the fallback file, private from the moment it exists.
    ///
    /// It used to be `fs::write` followed by a `set_permissions` whose error was discarded, which is
    /// two defects in three lines. The write creates at the umask, so a `0644` window stood open over
    /// the KEK between the two calls, and where the narrowing then failed nothing said so: the
    /// function returned `Ok` over a world-readable key. `replace_secret_file` creates at `0600` and
    /// renames into place, and a DACL that cannot be written is an error like any other.
    fn store_file(path: &Path, secret: &str) -> Result<(), String> {
        permaura_core::replace_secret_file(path, secret.as_bytes())
            .map_err(|e| format!("writing {} failed: {e}", path.display()))?;
        crate::restrict_to_owner(path)
            .map_err(|e| format!("restricting {} to its owner failed: {e}", path.display()))
    }

    /// Where this install records that systemd is provisioning the secret.
    ///
    /// Separate from [`Self::marker`], which claims the OS credential store, because the two mean
    /// different things and the recovery advice differs: one says "unlock your keyring", the other
    /// says "the unit stopped providing it".
    pub fn systemd_marker(&self) -> Result<std::path::PathBuf, String> {
        Ok(self.path()?.with_file_name(format!("{}.in-systemd-credential", self.file_name)))
    }

    /// The secret systemd provisioned for this unit, if it provisioned one.
    ///
    /// This is how the gateway can get TPM-sealed custody on Linux WITHOUT linking a TPM stack. The
    /// obvious route does not work: `tss-esapi` wraps the C library `tpm2-tss`, and both Linux
    /// gateway targets are static musl, which is the same wall that ruled out Secret Service. So
    /// systemd does the sealing (`systemd-creds encrypt --tpm2-device=auto`) and the unit asks for it
    /// back (`LoadCredentialEncrypted=`); this only ever reads the file systemd placed under
    /// `$CREDENTIALS_DIRECTORY`. A plain `LoadCredential=` is read the same way, with no sealing, so
    /// the TPM is involved only when the operator provisioned it that way.
    ///
    /// No platform gate is needed, since off systemd the variable is normally absent, but any process can set it, so a store that does not opt in through [`CredentialStore::operator_sets_custody`] ignores it in a release build.
    fn systemd_credential(&self) -> Option<String> {
        self.systemd_credential_in(DEBUG_BUILD, &IGNORED_CREDENTIALS_DIRECTORY)
    }

    /// [`Self::systemd_credential`] for a build of this kind, gated like the file request because a directory named by the environment would hand an app a secret of another process's choosing.
    fn systemd_credential_in(&self, debug_build: bool, reported: &AtomicBool) -> Option<String> {
        let dir = std::env::var_os("CREDENTIALS_DIRECTORY")?;
        if !self.custody_from_env(debug_build) {
            report_ignored("CREDENTIALS_DIRECTORY", reported);
            return None;
        }
        let raw = std::fs::read_to_string(Path::new(&dir).join(self.account)).ok()?;
        let trimmed = raw.trim_end_matches(['\n', '\r']).to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    /// Which custody holds this secret, asking the store first and the file second.
    ///
    /// Split out from [`CredentialStore::load`] so the ORDER (the part that decides whether an
    /// upgraded install keeps its vault) is testable without writing to a real OS keychain.
    fn resolve_from(&self, file: &Path, marker: &Path, custody: Custody, open: OpenEntry, read: FileRead) -> Result<Source, String> {
        self.decide_with(
            self.systemd_credential(),
            self.load_native(custody, open),
            file,
            marker,
            &self.systemd_marker()?,
            read,
        )
    }

    /// The decision table, given whatever the store said and whether the store has ever held this
    /// secret. Separated so the arms that cannot be produced on demand from a healthy machine are
    /// still testable.
    ///
    /// `claimed_by_store` is the marker (see [`CredentialStore::marker`]) and it is what makes the
    /// difference between the two ways a store can be unhelpful. A store that will not answer is a
    /// crisis on a machine that keeps its vault key in there, and a non-event on a machine that has
    /// never used it. Without that fact the only options were to refuse on both, which stops the app
    /// starting for anyone whose keyring is merely locked or unconfigured, or to mint on both, which
    /// re-keys a live vault. Neither is acceptable, and they are not actually the same question.
    /// Test-only shorthand for [`Self::decide_with`] with no systemd credential in play, which is the
    /// state every arm below the systemd one is about. Production always goes through `decide_with`
    /// via [`Self::resolve_from`].
    #[cfg(test)]
    fn decide(&self, native: Native, file: &Path, marker: &Path) -> Result<Source, String> {
        self.decide_with(
            None,
            native,
            file,
            marker,
            &marker.with_file_name("never-written.in-systemd-credential"),
            FileRead::Asked,
        )
    }

    /// [`Self::decide`] with the systemd credential passed in, so the arm can be tested without a
    /// systemd unit around the test.
    ///
    /// A provisioned credential outranks both other custodies, because it is the only one an operator
    /// stated explicitly: they ran `systemd-creds encrypt` and named it in the unit. It is still
    /// checked against the file, as the store's own answer is: two custodies holding different secrets is a
    /// refusal, not a race to see which is read first.
    fn decide_with(
        &self,
        systemd: Option<String>,
        native: Native,
        file: &Path,
        marker: &Path,
        systemd_marker: &Path,
        read: FileRead,
    ) -> Result<Source, String> {
        let read_file = || match read {
            FileRead::Asked => Self::load_file(file),
            FileRead::Skipped => Ok(None),
        };
        let claimed_by_systemd = systemd_marker.exists();
        if let Some(secret) = systemd {
            // Claim it, for the same reason the store has a marker: without one, a later boot that
            // cannot see the credential finds nothing anywhere and calls it a first run. A TPM seal
            // broken by a firmware update, a unit edited to drop LoadCredentialEncrypted=, a .cred
            // file deleted: all of those would then MINT over a live vault instead of saying what
            // happened. Observed on the first end-to-end run of this arm, before this existed.
            if !claimed_by_systemd {
                if let Err(e) = std::fs::write(systemd_marker, b"") {
                    log::warn!(
                        "permaura: {} came from systemd but the claim beside it could not be written \
                         ({e}); a boot without the credential would mint over this vault rather than \
                         refuse",
                        self.account
                    );
                }
            }
            return match read_file()? {
                Some(on_disk) if on_disk != secret => Err(format!(
                    "{} was provisioned to this unit by systemd AND is in {}, and the two do not \
                     match. Permaura will not guess which one your credentials were sealed under. \
                     Move the one you do not want aside and start again.",
                    self.account,
                    file.display()
                )),
                _ => Ok(Source::SystemdCredential(secret)),
            };
        }
        let claimed_by_store = marker.exists();
        // The store said, or implied, that it is not holding this secret. The file is asked next
        // whatever the reason, because a file that still holds the secret settles it either way.
        let without_the_store = |why: Option<String>| match read_file()? {
            Some(existing) => Ok(Source::File(existing)),
            // Nothing anywhere, and this unit was being given the secret by systemd until now. Same
            // rule as the store marker and the same reason: minting here re-keys a live vault.
            None if claimed_by_systemd => Err(format!(
                "{} is provisioned to this unit by systemd, and this launch did not receive it. \
                 Refusing to mint a replacement, which would re-key the credentials already sealed \
                 under the original. Check that the unit still has its LoadCredentialEncrypted= line \
                 and that the sealed file is readable. A TPM seal can also stop opening after a \
                 firmware update, which is the case worth knowing about. If it is genuinely gone, \
                 those credentials cannot be recovered and each connection needs reconnecting: \
                 delete {} to start over.",
                self.account,
                systemd_marker.display()
            )),
            // Nothing anywhere, and the store has never had anything of ours. There is nothing here
            // to mint over: a keyring we have never written to cannot be holding our KEK.
            None if !claimed_by_store => Ok(Source::Absent),
            // Nothing anywhere, and the marker says the store IS where this lives. Minting now is
            // exactly the unrecoverable move. Say so instead.
            None => Err(format!(
                "{} lives in this machine's OS credential store, and the store did not return it{}. \
                 Refusing to mint a replacement, which would re-key the credentials already sealed \
                 under the original. Make the store readable again, or start whichever program put it \
                 there, and try again. \
                 If the store has genuinely lost it, those credentials cannot be recovered and each \
                 connection will need reconnecting: delete {} to start over.",
                self.account,
                why.map(|w| format!(" ({w})")).unwrap_or_default(),
                marker.display()
            )),
        };
        match native {
            // The store answered, but the file is still asked, because a machine that ran the
            // earlier app-custody code can hold two DIFFERENT secrets: the app minted one into the store while
            // a gateway that could not read it minted another into the file. Preferring the store
            // there is the same silent re-key this crate exists to prevent, just reached from the other
            // side: nothing is orphaned by minting, it is orphaned by opening the vault with the
            // wrong one of two keys that both look valid. The hand-back path has always refused
            // this pair; the read path used to walk straight past it.
            Native::Found(secret) => match read_file()? {
                // The ordinary states: adoption removed the file, or the store write landed and the
                // delete did not, which `adopt_from_file` logs and carries on from.
                None => Ok(Source::Native(secret)),
                Some(on_disk) if on_disk == secret => Ok(Source::Native(secret)),
                // The store's copy wins for a store whose custody the environment cannot set: any program running as this user can write the file, and an earlier build's store writes left the file beside a newer stored copy, so a file that disagrees is neither trustworthy nor reliably the newer.
                Some(_) if !self.operator_sets_custody => {
                    log::warn!(
                        "permaura: {} in {} differs from the copy in the OS credential store; keeping the store's copy and removing the file",
                        self.account,
                        file.display()
                    );
                    Ok(Source::Native(secret))
                }
                Some(_) => Err(format!(
                    "{} is in this machine's OS credential store AND in {}, and the two do not \
                     match. Permaura will not guess which one your credentials were sealed under, \
                     because opening a vault with the wrong key of two valid-looking ones loses it \
                     exactly as thoroughly as minting a third. Move the one you do not want aside \
                     and start again.",
                    self.account,
                    file.display()
                )),
            },
            Native::Empty => without_the_store(Some("it reports nothing stored".to_string())),
            Native::NoStore => {
                // No store in this build at all. Harmless on an install that never had one, and the
                // marker is what catches the case that matters.
                without_the_store(Some("this build has no OS credential store".to_string()))
            }
            Native::Unavailable(why) => {
                // A store exists but not for this launch: a session with no bus to reach it, or a
                // binary that cannot hold a keychain item across its own updates. The marker catches
                // the case that matters: an install that adopted on a launch that COULD reach it.
                without_the_store(Some(why.to_string()))
            }
            Native::Failed(why) => {
                log::warn!(
                    "permaura: the OS credential store for {} could not be read ({why}){}",
                    self.account,
                    if read == FileRead::Asked { "; trying the owner-only file" } else { "" }
                );
                without_the_store(Some(why))
            }
        }
    }

    /// Move a file-held secret into the OS store, and only then stop keeping the file.
    ///
    /// Every step is best-effort and the caller already holds the secret, so a failure anywhere costs
    /// nothing: the file stays, this install keeps using it, and the next launch tries again. The
    /// read-back is not ceremony: a store that accepts a write and returns something else (or nothing)
    /// would otherwise leave us deleting the only copy of a key that opens the customer's vault.
    fn adopt_from_file(&self, secret: &str, file: &Path, marker: &Path, custody: Custody, open: OpenEntry) {
        if !custody.is_native() {
            return;
        }
        let Ok(entry) = open(&self.account_for_home()) else { return };
        if entry.set_password(secret).is_err() {
            return;
        }
        match entry.get_password() {
            Ok(read_back) if read_back == secret => {}
            _ => return,
        }
        // The marker goes down BEFORE the file comes up, and its failure cancels the deletion. The
        // file is what a later launch falls back to when the store is unreachable; without the marker
        // to explain the file's absence, that launch would read "no file, no store" as a first run.
        if let Err(e) = Self::claim_for_store(marker) {
            log::warn!(
                "permaura: {} is in the OS credential store but the marker recording that could not \
                 be written ({e}); keeping the on-disk copy",
                self.account
            );
            return;
        }
        match std::fs::remove_file(file) {
            Ok(()) => log::warn!(
                "permaura: {} moved into the OS credential store; the on-disk copy has been removed",
                self.account
            ),
            Err(e) => log::warn!(
                "permaura: {} copied into the OS credential store but the on-disk copy could not be removed: {e}",
                self.account
            ),
        }
    }

    /// Remove a plaintext copy left beside a secret the OS store already holds, claiming the store first for the reason [`Self::adopt_from_file`] does.
    fn retire_file(&self, file: &Path, marker: &Path) {
        if file.symlink_metadata().is_err() {
            return;
        }
        // Every load retries, and the desktop loads on a poll timer, so only the first failure is a warning.
        let level = || if RETIRE_FAILURE_REPORTED.swap(true, Ordering::Relaxed) { log::Level::Debug } else { log::Level::Warn };
        if let Err(e) = Self::claim_for_store(marker) {
            log::log!(
                level(),
                "permaura: {} is in the OS credential store but the marker recording that could not be written ({e}); keeping {}",
                self.account,
                file.display()
            );
            return;
        }
        if let Err(e) = std::fs::remove_file(file) {
            log::log!(level(), "permaura: {} is in the OS credential store but {} could not be removed: {e}", self.account, file.display());
        }
    }

    /// This machine's stored secret, or `None` if it has never been written.
    ///
    /// `None` is a strong claim (it is what makes the caller mint a new one), so it is only returned
    /// once BOTH custodies have been asked.
    pub fn load(&self) -> Result<Option<String>, String> {
        self.load_reading(FileRead::Asked)
    }

    /// [`Self::load`] for an app store that must never take a value from its owner-only file: the file is treated as absent, so it is never read, adopted or moved into the store, and with no item stored this is `Ok(None)`, or a refusal where a marker says the store, or systemd, holds the secret (a store whose custody is the file therefore finds nothing).
    ///
    /// A stored item is returned as [`Self::load`] returns it, and a file beside it is removed unread.
    pub fn load_without_file(&self) -> Result<Option<String>, String> {
        self.load_reading(FileRead::Skipped)
    }

    /// Whether a load asks the owner-only file in a build of this kind: never for a store kept in the data-protection keychain, whichever load the caller chose, so a planted file cannot be adopted into the item even through [`Self::load`].
    fn file_read_for(&self, read: FileRead, debug_build: bool) -> FileRead {
        if self.data_protection_in(debug_build).is_some() { FileRead::Skipped } else { read }
    }

    /// [`Self::load`], asking the owner-only file or not.
    fn load_reading(&self, read: FileRead) -> Result<Option<String>, String> {
        let read = self.file_read_for(read, DEBUG_BUILD);
        let file = self.path()?;
        let marker = self.marker()?;
        // One answer for the whole call. Asking twice could straddle a daemon starting or dying and
        // adopt into a store the read had already decided was not there.
        let custody = self.custody(DEBUG_BUILD, &IGNORED_VAULT_CUSTODY);
        self.load_in(&file, &marker, custody, &|account| self.entry_named(account), read)
    }

    /// Test-only shorthand for [`Self::load_in`] asking the owner-only file, as [`Self::load`] does.
    #[cfg(test)]
    fn load_from(&self, file: &Path, marker: &Path, custody: Custody, open: OpenEntry) -> Result<Option<String>, String> {
        self.load_in(file, marker, custody, open, FileRead::Asked)
    }

    /// [`Self::load`] with the paths, the custody and the store passed in, asking the owner-only file or not.
    fn load_in(&self, file: &Path, marker: &Path, custody: Custody, open: OpenEntry, read: FileRead) -> Result<Option<String>, String> {
        match self.resolve_from(file, marker, custody, open, read)? {
            // No adoption: systemd owns it, and writing a copy into the store or the file would
            // recreate exactly the two-custody divergence this crate exists to prevent.
            Source::SystemdCredential(secret) => Ok(Some(secret)),
            Source::Native(secret) => {
                if !self.operator_sets_custody {
                    self.retire_file(file, marker);
                }
                Ok(Some(secret))
            }
            Source::File(secret) => {
                self.adopt_from_file(&secret, file, marker, custody, open);
                Ok(Some(secret))
            }
            Source::Absent => Ok(None),
        }
    }

    /// Write the secret to the best custody available, preferring the OS store.
    ///
    /// The routine write: an OS-store item already standing is written in place and keeps its access list. A secret the app has just started goes through [`Self::store_fresh`] instead.
    ///
    /// On macOS an app store whose login keychain cannot be found or opened fails here, writing nothing anywhere, as does any refusal from an app store kept in the data-protection keychain and a value the store refuses as too long (Credential Manager's limit on Windows), which the owner-only file could not keep past the next load; any other refusal from the store gets the owner-only file.
    pub fn store(&self, secret: &str) -> Result<(), String> {
        self.store_to(
            &self.path()?,
            &self.marker()?,
            secret,
            self.custody(DEBUG_BUILD, &IGNORED_VAULT_CUSTODY),
            &|account| self.entry_named(account),
        )
        .map_err(String::from)
    }

    /// Write a secret the app has just started (a new sign-in session, a new approver key, the first audience pin) into an OS-store item of the app's own rather than one it finds.
    ///
    /// On macOS it removes the item standing under this service and account in the login keychain and adds a new one through the Keychain's add, so the item carries the app's access list rather than whatever list another program created it with; the module docs (the fresh write section) say what that does and does not guarantee. It fails, writing nothing anywhere, when the standing item cannot be removed, another program puts one back before the add, the login keychain cannot be found or opened, or the store refuses the add for any other reason: unlike [`Self::store`], it never falls back to the owner-only file, where a value another program forced there would stay the live copy.
    ///
    /// Callers serialize it with every load of the same store. [`Self::store_fresh_typed`] returns the same refusals as a [`StoreFreshError`], which is how a caller tells [`StoreFreshError::Occupied`] apart.
    ///
    /// Everywhere else, for a store whose custody its operator sets, and for a debug build told `PERMAURA_VAULT_CUSTODY=file`, this is [`Self::store`]: no other store gives an item an access list of its own, and the file has none to replace.
    pub fn store_fresh(&self, secret: &str) -> Result<(), String> {
        self.store_fresh_typed(secret).map_err(String::from)
    }

    /// [`Self::store_fresh`], with its refusal typed.
    pub fn store_fresh_typed(&self, secret: &str) -> Result<(), StoreFreshError> {
        self.store_fresh_to(
            &self.path().map_err(StoreFreshError::Failed)?,
            &self.marker().map_err(StoreFreshError::Failed)?,
            secret,
            self.custody(DEBUG_BUILD, &IGNORED_VAULT_CUSTODY),
            &|account| self.entry_named(account),
            own_item_add(),
        )
    }

    /// This machine's secret, generating and persisting a fresh one on genuine first run.
    ///
    /// The load-or-create every caller wants, in one place so nobody re-implements the half that
    /// matters. Minting happens on exactly one answer: [`Source::Absent`], which requires both
    /// custodies to have been asked and the marker to agree nothing was ever stored. An `Err` here is
    /// never "not found": it is the store refusing to answer for a secret the marker says it holds,
    /// and the caller must surface it rather than fall back to a fresh key.
    pub fn resolve_or_create(&self) -> Result<String, String> {
        self.resolve_or_create_unless(|| Ok(None))
    }

    /// [`Self::resolve_or_create`], refusing to mint when `in_use` finds something a fresh secret
    /// would orphan.
    ///
    /// The marker can only vouch for what sits beside it, and only while it survives. A caller whose
    /// secret protects data kept elsewhere (a store outside the home), or whose marker went missing
    /// while the store would not answer, reaches [`Source::Absent`] over a live vault; `in_use` is
    /// where it says so. `Ok(Some(what))` names what would be orphaned and refuses; `Err` means it
    /// could not tell, which refuses too, because minting is the one move that cannot be taken back.
    pub fn resolve_or_create_unless(
        &self,
        in_use: impl FnOnce() -> Result<Option<String>, String>,
    ) -> Result<String, String> {
        if let Some(existing) = self.load()? {
            if !existing.is_empty() {
                return Ok(existing);
            }
        }
        self.mint_unless_in_use(in_use, |fresh| self.store(fresh))
    }

    /// The minting half of [`Self::resolve_or_create_unless`], with the write passed in so the refusal
    /// is testable without a custody to write to.
    fn mint_unless_in_use(
        &self,
        in_use: impl FnOnce() -> Result<Option<String>, String>,
        persist: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<String, String> {
        match in_use() {
            Ok(None) => {}
            Ok(Some(what)) => {
                return Err(format!(
                    "refusing to mint a new {}: none was found in any custody on this machine, and {what}",
                    self.account
                ))
            }
            Err(why) => {
                return Err(format!(
                    "refusing to mint a new {}: none was found in any custody on this machine, and whether anything is already sealed under one could not be established ({why})",
                    self.account
                ))
            }
        }
        let fresh = generate_secret();
        persist(&fresh)?;
        Ok(fresh)
    }

    /// Remove this secret from every custody: the OS store entry, the marker, and the owner-only file.
    ///
    /// The primitive a sign-out and an uninstall need.
    ///
    /// It replaced a hand-back that moved the secret from the store into the owner-only file, which
    /// could never mean "sign me out": it *preserves* the value, so a sign-out through it ended with
    /// the credential still on disk. See "Who calls this" in the module docs for why that function is
    /// gone rather than deprecated.
    ///
    /// Order is the reverse of [`CredentialStore::adopt_from_file`] and for the same reason held
    /// upside down: the store entry goes FIRST, because the failure worth designing against is a
    /// half-finished forget that leaves the secret somewhere while the caller believes it is gone. A
    /// marker left behind with the entry already deleted is harmless (the next resolution finds no
    /// file either, and `Source::Absent` is the truth), whereas an entry left behind after the file
    /// and marker have gone is a live credential nothing points at any more.
    ///
    /// Best-effort by design, and it reports what it could not do rather than stopping at the first
    /// failure: a caller signing out wants every copy it can reach removed, not the first two.
    ///
    /// A store kept in the data-protection keychain leaves alone the item an earlier build kept in the login keychain under the same name: removing an item this app did not add raises a Keychain authorization dialog, and the forget would wait on it.
    pub fn forget(&self) -> Result<(), String> {
        // Account resolved HERE, beside the paths, and passed down with them. It used to be resolved
        // inside, which meant the two halves of one forget were read from the environment at
        // different moments, and a caller whose `PERMAURA_HOME` moved in between deleted a file in
        // one home and a credential belonging to another.
        self.forget_from(&self.path()?, &self.marker()?, &self.account_for_home(), &|account| self.entry_named(account))
    }

    /// The testable core of [`CredentialStore::forget`], with the paths AND the account passed in:
    /// same reason as [`CredentialStore::decide`]. Resolving any of them inside would make every test
    /// of this reach the developer's real `~/.permaura`, which is a mistake this repository has
    /// already made twice.
    ///
    /// The account was the third one. It stayed resolved internally while the paths were lifted out,
    /// so this function still reached the machine's real Keychain entry from a test pointed at a
    /// scratch directory, and a suite that raced `PERMAURA_HOME` deleted a live vault KEK with it.
    /// The store is the fourth, so a test's forget opens a store of its own rather than this machine's.
    fn forget_from(&self, file: &Path, marker: &Path, account: &str, open: OpenEntry) -> Result<(), String> {
        self.forget_entry(open(account), file, marker)
    }

    /// [`CredentialStore::forget_from`] with the entry already opened, or not, so the arm where the
    /// store cannot even be addressed is testable: no backend, the mock included, fails `Entry::new`
    /// on demand.
    fn forget_entry(
        &self,
        entry: Result<Entry, String>,
        file: &Path,
        marker: &Path,
    ) -> Result<(), String> {
        let mut failures: Vec<String> = Vec::new();

        match entry {
            Ok(entry) => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => failures.push(format!("the OS credential store entry ({e})")),
            },
            // Never a skip: an entry this call could not open is one it cannot say is gone.
            Err(e) => failures.push(format!("the OS credential store entry could not be opened ({e})")),
        }
        for path in [marker, file] {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    failures.push(format!("{} ({e})", path.display()));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!("{} could not be fully removed: {}", self.account, failures.join("; ")))
        }
    }

    /// [`CredentialStore::store`] with the file path and the custody answer passed in, so the branches
    /// that must reach the disk rather than a mock that forgets (`NoStore`, and the headless-Linux
    /// `Unavailable`) are testable on every platform, and against a scratch path rather than the real
    /// Permaura home.
    fn store_to(
        &self,
        file: &Path,
        marker: &Path,
        secret: &str,
        custody: Custody,
        open: OpenEntry,
    ) -> Result<(), StoreFreshError> {
        // Whichever branch runs, the marker ends up agreeing with where the secret actually landed.
        // A marker left claiming a store that does not have it would refuse every future launch.
        if !custody.is_native() {
            let _ = std::fs::remove_file(marker);
            return Self::store_file(file, secret).map_err(StoreFreshError::Failed);
        }
        let account = self.account_for_home();
        let entry = match open(&account) {
            Ok(entry) => entry,
            // Never for a data-protection store: nothing reads its file.
            Err(why) if self.data_protection_in(DEBUG_BUILD).is_some() => {
                return Err(StoreFreshError::Failed(self.not_written(&account, &why, DATA_PROTECTION_REMEDY)))
            }
            Err(why) => return self.store_file_instead(file, marker, secret, &why).map_err(StoreFreshError::Failed),
        };
        match entry.set_password(secret) {
            Ok(()) => {
                self.landed_in_store(file, marker);
                Ok(())
            }
            // The store will refuse this value every time, so the owner-only file would hold the only copy of it until the next load the store answers, which keeps the earlier item and removes the file: the write would be lost while it reported success.
            Err(e @ keyring::Error::TooLong(..)) => Err(StoreFreshError::Failed(self.not_written(
                &account,
                &format!("{e}: the value is too long for this store ever to hold, so nothing was written anywhere in its place and the earlier value stays in use"),
                "Report this to Permaura with the item's name; it cannot be fixed from this machine.",
            ))),
            Err(e) => match (missing_login_keychain(&e), data_protection_refusal(&e)) {
                (Some(why), _) => Err(self.login_keychain_refusal(&account, why)),
                (None, Some(why)) => Err(StoreFreshError::Failed(self.not_written(
                    &account,
                    &format!("{why}, and nothing was written anywhere in its place"),
                    DATA_PROTECTION_REMEDY,
                ))),
                (None, None) => self
                    .store_file_instead(
                        file,
                        marker,
                        secret,
                        &format!("writing {} to the credential store failed: {e}", self.account),
                    )
                    .map_err(StoreFreshError::Failed),
            },
        }
    }

    /// The refusal of a write whose login keychain could not be found or opened.
    fn login_keychain_refusal(&self, account: &str, why: &NoLoginKeychain) -> StoreFreshError {
        StoreFreshError::LoginKeychainUnavailable(self.not_written(
            account,
            &format!("{why}, and nothing was written anywhere in its place"),
            "Open Keychain Access and confirm your login keychain is there and unlocked, then try again.",
        ))
    }

    /// A write's refusal as a person reads it: the item by service and account, why, and what to do.
    fn not_written(&self, account: &str, why: &str, remedy: &str) -> String {
        format!("the {} item named {} with account {account} was not written: {why}. {remedy}", self.keychain_name(), self.service)
    }

    /// What to do about an item that stands where a fresh write needs none: in the data-protection keychain only this app can have put it there.
    fn remove_item_remedy(&self, account: &str) -> String {
        if self.data_protection_in(DEBUG_BUILD).is_some() {
            return "Quit the app, open it again, and try again.".into();
        }
        format!(
            "Open Keychain Access, delete the login keychain item named {} with account {account}, and try again.",
            self.service
        )
    }

    /// What follows a write the OS store took: the marker claims the store, and an app store's plaintext copy goes.
    fn landed_in_store(&self, file: &Path, marker: &Path) {
        if let Err(e) = Self::claim_for_store(marker) {
            // Not fatal: the secret is in the store and reads fine today. What is lost is the
            // ability to tell, on some later launch where the store has gone quiet, that this
            // machine had a KEK in there at all.
            log::warn!(
                "permaura: {} was written to the OS credential store but the marker recording \
                 that could not be written ({e})",
                self.account
            );
        }
        if !self.operator_sets_custody {
            match std::fs::remove_file(file) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // The store holds the secret and every read prefers it and retries the removal, so the write stands.
                Err(e) => log::warn!(
                    "permaura: {} was written to the OS credential store but the plaintext copy in {} could not be removed: {e}",
                    self.account,
                    file.display()
                ),
            }
        }
    }

    /// The owner-only file, for a write the OS store refused.
    fn store_file_instead(&self, file: &Path, marker: &Path, secret: &str, why: &str) -> Result<(), String> {
        log::warn!(
            "permaura: could not write {} to the OS credential store ({why}); writing the owner-only file",
            self.account
        );
        let _ = std::fs::remove_file(marker);
        Self::store_file(file, secret)
    }

    /// [`CredentialStore::store_fresh`] with the paths, the custody, the store and its add passed in, for the reason [`CredentialStore::store_to`] takes them.
    fn store_fresh_to(
        &self,
        file: &Path,
        marker: &Path,
        secret: &str,
        custody: Custody,
        open: OpenEntry,
        add: Option<AddOwnItem>,
    ) -> Result<(), StoreFreshError> {
        let add = match add {
            Some(add) if custody.is_native() && !self.operator_sets_custody => add,
            _ => return self.store_to(file, marker, secret, custody, open),
        };
        let account = self.account_for_home();
        let entry = match open(&account) {
            Ok(entry) => entry,
            Err(why) => {
                return Err(StoreFreshError::Failed(self.not_written(
                    &account,
                    &format!("{why}, and nothing was written anywhere in its place"),
                    "Try again, and report it if it keeps happening.",
                )))
            }
        };
        // Before the item, so an interruption after the removal reads as nothing stored (or as the owner-only file an earlier refused write left) rather than a refusal over a store that has lost it.
        let had_marker = match std::fs::remove_file(marker) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                return Err(StoreFreshError::Failed(self.not_written(
                    &account,
                    &format!("{} could not be removed ({e})", marker.display()),
                    "Check that this app can write to that folder, then try again.",
                )))
            }
        };
        let put_marker_back = || {
            if had_marker {
                if let Err(claim) = Self::claim_for_store(marker) {
                    log::warn!("permaura: {} could not be put back ({claim})", marker.display());
                }
            }
        };
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => {
                put_marker_back();
                return Err(match (missing_login_keychain(&e), data_protection_refusal(&e)) {
                    (Some(why), _) => self.login_keychain_refusal(&account, why),
                    (None, Some(why)) => StoreFreshError::Failed(self.not_written(
                        &account,
                        &format!("the item already under that name could not be removed: {why}"),
                        DATA_PROTECTION_REMEDY,
                    )),
                    (None, None) => StoreFreshError::Failed(self.not_written(
                        &account,
                        &format!("the item already under that name could not be removed ({e})"),
                        &self.remove_item_remedy(&account),
                    )),
                });
            }
        }
        match add(&entry, secret) {
            Ok(()) => {
                self.landed_in_store(file, marker);
                Ok(())
            }
            Err(AddRefused::Occupied) => {
                put_marker_back();
                Err(StoreFreshError::Occupied(self.not_written(
                    &account,
                    "an item still stood under that name when this app added its own (the removal did not take, or another program put one back), and nothing was written into that item",
                    &self.remove_item_remedy(&account),
                )))
            }
            Err(AddRefused::NoLoginKeychain(why)) => {
                put_marker_back();
                Err(self.login_keychain_refusal(&account, &why))
            }
            // The marker stays removed: the removal took as far as the store can say, so this reads as an interruption at the add does.
            Err(AddRefused::Failed(why)) => Err(StoreFreshError::Failed(self.not_written(
                &account,
                &format!("the {} refused the new item ({why}), and nothing was written anywhere in its place", self.keychain_name()),
                if self.data_protection_in(DEBUG_BUILD).is_some() {
                    DATA_PROTECTION_REMEDY
                } else {
                    "Open Keychain Access and confirm your login keychain is unlocked and can be written to, then try again."
                },
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for whichever of the two real reasons this build produces; `decide` only ever passes
    /// it through into the refusal text.
    const TEST_REASON: &str = "this session has no Secret Service to reach";

    /// A scratch directory and a store whose native half is guaranteed empty: a service/account pair
    /// nothing has ever written. Nothing here writes to a real OS keychain: the tests drive
    /// `resolve_from`, which only ever READS the store.
    fn scratch(name: &'static str) -> (CredentialStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "permaura-cred-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let store = CredentialStore {
            service: "com.permaura.test.never-written",
            account: name,
            file_name: name,
            needs_stable_code_identity: false,
            operator_sets_custody: false,
            keychain_access_group: None,
        };
        (store, dir.join(name))
    }

    /// Run `f` with `PERMAURA_HOME` pointed somewhere, restoring it afterwards. Serialised, because
    /// the env is process-wide and these assertions are about what it resolves to.
    fn with_home<T>(home: &std::path::Path, f: impl FnOnce() -> T) -> T {
        with_homes(home, None, f)
    }

    /// [`with_home`], with `HOME` pointed somewhere too when it is given; a test that sets either variable, or asserts on what it resolves to, does so inside one of these.
    fn with_homes<T>(permaura_home: &std::path::Path, home: Option<&std::path::Path>, f: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = [("PERMAURA_HOME", std::env::var_os("PERMAURA_HOME")), ("HOME", std::env::var_os("HOME"))];
        std::env::set_var("PERMAURA_HOME", permaura_home);
        if let Some(home) = home {
            std::env::set_var("HOME", home);
        }
        let out = f();
        for (name, value) in prev {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        out
    }

    /// The store a test hands in where its custody means no store is ever opened.
    fn no_store(account: &str) -> Result<Entry, String> {
        Err(format!("{account}: this test opens no OS credential store"))
    }

    /// Serializes the tests that set `PERMAURA_VAULT_CUSTODY` or `CREDENTIALS_DIRECTORY`.
    static CUSTODY_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `f` with `name` set to `value`, restoring it afterwards, under [`CUSTODY_ENV`].
    fn with_custody_env<T>(name: &str, value: &std::ffi::OsStr, f: impl FnOnce() -> T) -> T {
        let _guard = CUSTODY_ENV.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os(name);
        std::env::set_var(name, value);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        out
    }

    /// A marker path for a store that has never held this secret.
    fn never_claimed(file: &Path) -> std::path::PathBuf {
        let m = file.with_extension("in-os-store");
        std::fs::remove_file(&m).ok();
        m
    }

    /// A marker path for a store that HAS held this secret, laid down for real so `decide` sees it
    /// the way it will in production.
    fn claimed(file: &Path) -> std::path::PathBuf {
        let m = file.with_extension("in-os-store");
        CredentialStore::claim_for_store(&m).expect("marker");
        m
    }

    /// A lost marker and a store that will not answer are, together, indistinguishable
    /// from a first run, so the decision table says `Absent`. What stops the mint is the caller's own
    /// evidence that something is sealed under the missing secret.
    #[test]
    fn a_lost_marker_and_a_store_that_will_not_answer_mint_nothing_over_a_live_vault() {
        let (store, file) = scratch("lost-marker");
        std::fs::remove_file(&file).ok();
        let marker = never_claimed(&file);
        assert_eq!(
            store.decide(Native::Failed("the keyring is locked".into()), &file, &marker).unwrap(),
            Source::Absent,
            "precondition: nothing on this machine can say a secret was ever stored"
        );
        let refused = store
            .mint_unless_in_use(
                || Ok(Some("/srv/permaura/gateway.db holds 3 credentials sealed under it".into())),
                |_| panic!("nothing may be written"),
            )
            .expect_err("a live vault is not minted over");
        assert!(refused.contains("/srv/permaura/gateway.db holds 3 credentials"), "{refused}");
        assert!(refused.contains("refusing to mint"), "{refused}");
    }

    /// Not knowing is not "nothing there": an unreadable store refuses the mint as well.
    #[test]
    fn a_vault_that_cannot_be_examined_is_not_minted_over() {
        let (store, _) = scratch("unexaminable");
        let refused = store
            .mint_unless_in_use(|| Err("the database is locked".into()), |_| panic!("nothing may be written"))
            .expect_err("an unreadable vault is not minted over");
        assert!(refused.contains("the database is locked"), "{refused}");
    }

    /// And a genuinely fresh home still gets its secret, written exactly once.
    #[test]
    fn a_fresh_home_with_nothing_sealed_mints_once() {
        let (store, _) = scratch("fresh-mint");
        let mut written = Vec::new();
        let minted = store.mint_unless_in_use(|| Ok(None), |s| {
            written.push(s.to_string());
            Ok(())
        });
        let minted = minted.expect("a first run provisions a secret");
        assert!(!minted.is_empty());
        assert_eq!(written, vec![minted]);
    }

    /// THE migration property. A secret already in the file must be found and returned, never treated
    /// as absent: answering `Absent` here is what would mint a fresh KEK over a live vault.
    #[test]
    fn a_file_held_secret_is_found_even_when_the_native_store_is_empty() {
        let (store, file) = scratch("adopt-me");
        CredentialStore::store_file(&file, "the-original-secret").unwrap();

        let found = store.resolve_from(&file, &never_claimed(&file), Custody::NoStore, &no_store, FileRead::Asked).expect("resolve must not error");
        assert_eq!(found, Source::File("the-original-secret".into()));

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The pair the earlier app-custody code produced and this one refuses: the app minted into the store while a
    /// gateway that could not read the store minted its own into the file. Both look like valid keys
    /// and only one sealed the vault, so opening it with the wrong one loses the vault exactly as
    /// thoroughly as minting a third would. The hand-back always refused this pair; the read path
    /// walked straight past it and preferred the store.
    #[test]
    fn the_read_path_refuses_a_store_and_file_that_disagree() {
        let (store, file) = scratch("read-disagree");
        let store = CredentialStore { operator_sets_custody: true, ..store };
        CredentialStore::store_file(&file, "the-key-the-vault-was-sealed-under").unwrap();

        let err = store
            .decide(Native::Found("a-different-key-from-the-store".into()), &file, &never_claimed(&file))
            .expect_err("a disagreement must not be resolved by preferring the store");
        assert!(err.contains("do not match"), "unexpected message: {err}");

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Adoption removes the file, so this is the ordinary state of an adopted install and must stay
    /// a plain read rather than becoming a refusal.
    #[test]
    fn a_store_held_secret_with_no_file_is_returned() {
        let (store, file) = scratch("read-store-only");
        assert_eq!(
            store.decide(Native::Found("in-the-store".into()), &file, &claimed(&file)).unwrap(),
            Source::Native("in-the-store".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// `adopt_from_file` logs and carries on when the store write lands and the file delete does not,
    /// so an AGREEING pair is a real state of a healthy install. Refusing it would strand them.
    #[test]
    fn a_store_and_file_holding_the_same_secret_is_not_a_disagreement() {
        let (store, file) = scratch("read-agree");
        CredentialStore::store_file(&file, "the-same-key").unwrap();
        assert_eq!(
            store.decide(Native::Found("the-same-key".into()), &file, &claimed(&file)).unwrap(),
            Source::Native("the-same-key".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The account is a parameter so that a test can name a scratch one, and this pins that it is
    /// actually honoured. Without it the deletion silently addresses whatever the ambient
    /// environment resolves to, which on a developer's machine is their live vault key.
    #[test]
    fn forget_deletes_the_account_it_is_given() {
        let (store, file) = scratch("forget-named-account");
        CredentialStore::store_file(&file, "a-secret").unwrap();
        let marker = claimed(&file);
        let keychain = TestKeychain::holding("a-secret");
        let opened = std::cell::RefCell::new(Vec::new());
        let open = |account: &str| {
            opened.borrow_mut().push(account.to_string());
            keychain.open()(account)
        };

        let scratch_account = "permaura-test-account-that-does-not-exist";
        store.forget_from(&file, &marker, scratch_account, &open).expect("forget must succeed");

        assert_eq!(opened.into_inner(), vec![scratch_account.to_string()], "the store entry opened must be the account given");
        assert_eq!(keychain.held(), None);
        assert!(!file.exists());
        assert!(!marker.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A sign-out has to actually sign out, which means every custody and not just the one this launch
    /// happened to use.
    #[test]
    fn forget_removes_the_file_and_the_marker() {
        let (store, file) = scratch("forget-both");
        CredentialStore::store_file(&file, "a-secret").unwrap();
        let marker = claimed(&file);
        assert!(file.exists() && marker.exists());

        // A scratch account and a test's store, not this machine's. Before the account was a parameter, this line deleted the developer's real `vault-kek` every time it ran green.
        store
            .forget_from(&file, &marker, "forget-both-scratch-account", &TestKeychain::holding("a-secret").open())
            .expect("forget must succeed");

        assert!(!file.exists(), "the owner-only copy must be gone");
        assert!(!marker.exists(), "nothing may still claim the store");
        assert_eq!(
            store.resolve_from(&file, &marker, Custody::NoStore, &no_store, FileRead::Asked).unwrap(),
            Source::Absent,
            "after a forget the next resolution must see a genuine first run"
        );

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Forgetting what was never there is not an error. A sign-out on a machine that never signed in,
    /// or a second one after the first, must not surface a failure the user cannot act on.
    #[test]
    fn forget_is_idempotent_and_quiet_on_a_clean_machine() {
        let (store, file) = scratch("forget-clean");
        let marker = never_claimed(&file);
        let scratch_account = "permaura-test-clean-machine-account";
        let keychain = TestKeychain::default();
        store
            .forget_from(&file, &marker, scratch_account, &keychain.open())
            .expect("forgetting nothing must succeed");
        store
            .forget_from(&file, &marker, scratch_account, &keychain.open())
            .expect("and again");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A store entry that cannot even be opened is one this forget cannot show is gone, so the
    /// sign-out that depends on it must hear about it rather than report a clean removal over a live
    /// credential. The copies it can reach still go.
    #[test]
    fn forget_fails_when_the_store_entry_cannot_be_opened() {
        let (store, file) = scratch("forget-unopenable");
        CredentialStore::store_file(&file, "a-secret").unwrap();
        let marker = claimed(&file);

        let unopenable =
            Err("opening the credential store entry for forget-unopenable failed: refused by the test".into());
        let err = store
            .forget_entry(unopenable, &file, &marker)
            .expect_err("an entry that could not be opened must fail the forget");

        assert!(err.contains("the OS credential store entry could not be opened"), "{err}");
        assert!(err.contains("refused by the test"), "the store's own reason must survive: {err}");
        assert!(!file.exists(), "the owner-only copy must still be removed");
        assert!(!marker.exists(), "the marker must still be removed");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The controls for the arm above, on a mock credential handed in directly so neither can reach
    /// a real OS store whatever backend features the build unified: nothing stored is already gone,
    /// and a store that refuses the deletion fails the forget.
    #[test]
    fn forget_treats_a_missing_entry_as_gone_and_a_refused_deletion_as_a_failure() {
        let (store, file) = scratch("forget-mock-entry");
        let marker = never_claimed(&file);

        let empty = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        store
            .forget_entry(Ok(empty), &file, &marker)
            .expect("an entry with nothing in it is not an error");

        let refusing = keyring::mock::MockCredential::default();
        refusing.set_error(keyring::Error::Invalid("access".into(), "denied by the test".into()));
        let err = store
            .forget_entry(Ok(Entry::new_with_credential(Box::new(refusing))), &file, &marker)
            .expect_err("a refused deletion must fail the forget");
        assert!(err.contains("the OS credential store entry"), "{err}");
        assert!(err.contains("denied by the test"), "{err}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A credential systemd provisioned outranks both other custodies, and is never adopted.
    #[test]
    fn a_systemd_credential_is_used_and_not_copied_anywhere() {
        let (store, file) = scratch("systemd-wins");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        assert_eq!(
            store
                .decide_with(Some("from-the-tpm".into()), Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked)
                .unwrap(),
            Source::SystemdCredential("from-the-tpm".into())
        );
        assert!(!file.exists(), "systemd owns the plaintext; nothing here may write a second copy");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Even the highest-priority source does not get to win an argument. Same rule as a store and a
    /// file that disagree: guessing costs the vault, refusing costs a message.
    #[test]
    fn a_systemd_credential_that_disagrees_with_the_file_is_a_refusal() {
        let (store, file) = scratch("systemd-disagree");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        CredentialStore::store_file(&file, "the-key-the-vault-was-sealed-under").unwrap();
        let err = store
            .decide_with(Some("a-different-one".into()), Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked)
            .expect_err("a disagreement must not be resolved by ranking the sources");
        assert!(err.contains("do not match"), "unexpected message: {err}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An agreeing pair is the ordinary state of a machine migrated onto a systemd credential while
    /// its old file is still there. Refusing it would strand exactly the installs doing the right
    /// thing.
    #[test]
    fn a_systemd_credential_matching_the_file_is_not_a_disagreement() {
        let (store, file) = scratch("systemd-agree");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        CredentialStore::store_file(&file, "same-key").unwrap();
        assert_eq!(
            store
                .decide_with(Some("same-key".into()), Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked)
                .unwrap(),
            Source::SystemdCredential("same-key".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// With no unit around it, nothing changes: absent `CREDENTIALS_DIRECTORY`, the table behaves
    /// exactly as it did before this source existed.
    #[test]
    fn no_systemd_credential_leaves_the_existing_table_untouched() {
        let (store, file) = scratch("systemd-absent");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        CredentialStore::store_file(&file, "a-secret").unwrap();
        assert_eq!(
            store.decide_with(None, Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked).unwrap(),
            Source::File("a-secret".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The defect this claim exists for, caught on the first end-to-end run: with the credential gone
    /// and nothing else anywhere, the table called it a first run and minted over a live vault. A TPM
    /// seal broken by a firmware update looks exactly like this.
    #[test]
    fn a_lost_systemd_credential_refuses_rather_than_minting() {
        let (store, file) = scratch("systemd-lost");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        std::fs::write(&sysm, b"").unwrap();

        let err = store
            .decide_with(None, Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked)
            .expect_err("a vanished credential must not be answered with a fresh secret");
        assert!(err.contains("did not receive it"), "unexpected message: {err}");

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// And the claim is written the first time it is used, or the refusal above can never fire.
    #[test]
    fn using_a_systemd_credential_records_the_claim() {
        let (store, file) = scratch("systemd-claims");
        let sysm = file.with_file_name("sys.in-systemd-credential");
        assert!(!sysm.exists());

        store
            .decide_with(Some("k".into()), Native::Empty, &file, &never_claimed(&file), &sysm, FileRead::Asked)
            .unwrap();

        assert!(sysm.exists(), "without this, a later boot mints instead of refusing");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Nothing in either custody is the only case that may answer Absent.
    #[test]
    fn a_machine_with_neither_custody_populated_reports_absent() {
        let (store, file) = scratch("absent");
        assert_eq!(store.resolve_from(&file, &never_claimed(&file), Custody::NoStore, &no_store, FileRead::Asked).unwrap(), Source::Absent);
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A trailing newline in a hand-edited file must not become part of the secret: a KEK with a
    /// stray `\n` decrypts nothing and looks like key loss.
    #[test]
    fn a_trailing_newline_is_not_part_of_the_secret() {
        let (store, file) = scratch("newline");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "secret\n").unwrap();
        assert_eq!(store.resolve_from(&file, &never_claimed(&file), Custody::NoStore, &no_store, FileRead::Asked).unwrap(), Source::File("secret".into()));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The fallback file holds a key in the clear, so it must be owner-only wherever modes exist.
    #[cfg(unix)]
    #[test]
    fn the_fallback_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_store, file) = scratch("perm-check");
        CredentialStore::store_file(&file, "secret").unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the fallback file must be owner-only, got {mode:o}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The trap this module exists to avoid, pinned so nobody re-opens it by adding a keyring feature
    /// without adding the platform to `HAS_NATIVE_STORE`. Drives the no-store branch explicitly, so it
    /// fires on macOS too rather than only on the platforms that already lack a store.
    ///
    /// Where there is no compiled-in store, `keyring` resolves to an in-memory mock whose `set_password`
    /// returns Ok and whose value is gone at exit. If `store` trusted that, the file would never be
    /// written and the KEK would not survive a restart: every sealed credential orphaned, silently.
    /// So on such a build the write must land on disk.
    #[test]
    fn without_a_native_store_the_secret_actually_reaches_the_disk() {
        let (store, file) = scratch("must-persist");
        store.store_to(&file, &never_claimed(&file), "a-secret", Custody::NoStore, &no_store).expect("store must not error");
        assert_eq!(
            CredentialStore::load_file(&file).unwrap().as_deref(),
            Some("a-secret"),
            "with no OS store the secret must be written to disk, not into a mock that forgets it"
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The marker is the whole difference between a crisis and a non-event, so both halves are
    /// asserted together. Same store failure, same empty file, opposite answers.
    ///
    /// This replaced a flat "a failed store with no local copy is always an error". That was safe but
    /// unshippable: KeePassXC owns `org.freedesktop.secrets` and exposes nothing usable until its
    /// database is open with a group exposed, so every first run on a machine running it refused to
    /// start. Measured, on the Ubuntu VM. A store this machine has never written to cannot be holding
    /// this machine's KEK, and there is nothing to protect by refusing.
    #[test]
    fn a_failed_store_is_a_crisis_only_where_the_secret_was_kept_in_it() {
        let (store, file) = scratch("store-broke");

        assert_eq!(
            store.decide(Native::Failed("keyring is locked".into()), &file, &never_claimed(&file)).unwrap(),
            Source::Absent,
            "a store that never held this secret is just an absent store: first run, file custody"
        );

        let err = store
            .decide(Native::Failed("keyring is locked".into()), &file, &claimed(&file))
            .expect_err("a store the marker says holds the secret must not report first run");
        assert!(err.contains("Refusing to mint a replacement"), "unexpected message: {err}");

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The hole this marker was actually written to close, and the one that had nothing to do with
    /// locking. An install that adopted on a desktop session has NO file left, so a later launch from
    /// a session with no bus reaches `Unavailable` with nothing on disk. Reading that as a first run
    /// mints a second KEK and orphans every credential sealed under the first.
    #[test]
    fn an_adopted_install_never_mints_just_because_this_session_has_no_store() {
        let (store, file) = scratch("adopted-then-no-bus");

        let err = store
            .decide(Native::Unavailable(TEST_REASON), &file, &claimed(&file))
            .expect_err("an adopted install with no reachable store must refuse, not mint");
        assert!(err.contains("Refusing to mint a replacement"), "unexpected message: {err}");

        assert_eq!(
            store.decide(Native::Unavailable(TEST_REASON), &file, &never_claimed(&file)).unwrap(),
            Source::Absent,
            "the same shape on an install that never adopted really is a first run"
        );

        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A store that says "nothing stored" is not believed either, once the marker says it should
    /// have been holding something. That covers a locked store answering an attribute search with an
    /// empty result instead of an error, and equally a machine restored from backup onto an empty
    /// keyring: in both cases the sealed vault is real and the original key is the only one that
    /// opens it.
    #[test]
    fn an_empty_store_is_not_believed_where_the_marker_says_it_held_the_secret() {
        let (store, file) = scratch("empty-but-claimed");
        let err = store
            .decide(Native::Empty, &file, &claimed(&file))
            .expect_err("an empty store that should have held the secret must not report first run");
        assert!(err.contains("Refusing to mint a replacement"), "unexpected message: {err}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The file still wins over every unhappy store answer, marker or no marker. A machine part-way
    /// through adoption has both, and the file is the copy known to work.
    #[test]
    fn the_file_outranks_every_unhappy_store_answer() {
        let (store, file) = scratch("file-outranks");
        CredentialStore::store_file(&file, "the-real-one").unwrap();
        for with_marker in [true, false] {
            let marker =
                if with_marker { self::tests::claimed(&file) } else { self::tests::never_claimed(&file) };
            for native in [
                Native::Empty,
                Native::Unavailable(TEST_REASON),
                Native::NoStore,
                Native::Failed("locked".into()),
            ] {
                assert_eq!(
                    store.decide(native, &file, &marker).unwrap(),
                    Source::File("the-real-one".into()),
                    "with_marker={with_marker}"
                );
            }
        }
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The same failed store IS recoverable when the file still holds the secret    /// The same failed store IS recoverable when the file still holds the secret: degraded custody
    /// beats refusing to run.
    #[test]
    fn a_failed_store_falls_back_to_the_local_copy_when_there_is_one() {
        let (store, file) = scratch("store-broke-but-file");
        CredentialStore::store_file(&file, "still-here").unwrap();
        assert_eq!(
            store.decide(Native::Failed("keychain is locked".into()), &file, &never_claimed(&file)).unwrap(),
            Source::File("still-here".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// `Empty` is trusted here, unconditionally, which is only safe because whether the store was in
    /// a position to answer `Empty` is settled upstream in [`CredentialStore::load_native`]. Pinned so
    /// that if anyone ever routes a locked store to this arm, the pairing below stops making sense and
    /// they have to come and read why.
    #[test]
    fn an_empty_store_defers_to_the_file_and_only_then_reports_first_run() {
        let (store, file) = scratch("empty-store");

        CredentialStore::store_file(&file, "still-only-in-the-file").unwrap();
        assert_eq!(
            store.decide(Native::Empty, &file, &never_claimed(&file)).unwrap(),
            Source::File("still-only-in-the-file".into()),
            "an empty store never overrides a file that still holds the secret"
        );

        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            store.decide(Native::Empty, &file, &never_claimed(&file)).unwrap(),
            Source::Absent,
            "empty store, no file: the one shape that is genuinely a first run"
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The headless-Linux read. A box with no session bus must reach the same conclusion as a
    /// platform with no store compiled in: the file is the custody, and nothing in the empty native
    /// store makes it otherwise.
    #[test]
    fn an_unreachable_store_reads_the_file_exactly_as_a_missing_one_does() {
        let (store, file) = scratch("headless-read");
        CredentialStore::store_file(&file, "kek-from-the-file").unwrap();
        assert_eq!(
            store.resolve_from(&file, &never_claimed(&file), Custody::Unavailable(TEST_REASON), &no_store, FileRead::Asked).unwrap(),
            Source::File("kek-from-the-file".into())
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The headless-Linux FIRST run, and the reason `Unavailable` is a separate variant from `Failed`
    /// rather than folded into it. A server that has no Secret Service and no file is a genuinely new
    /// install: it has to be allowed to mint, or the app never starts anywhere without a desktop.
    #[test]
    fn an_unreachable_store_with_no_file_is_a_first_run() {
        let (store, file) = scratch("headless-first-run");
        assert_eq!(store.resolve_from(&file, &never_claimed(&file), Custody::Unavailable(TEST_REASON), &no_store, FileRead::Asked).unwrap(), Source::Absent);
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An unreachable store must not swallow the write. This is the `NoStore` mock trap wearing the
    /// other hat: on Linux `keyring` IS compiled in, so a write attempt would reach a real backend and
    /// fail. If `store_to` treated compiled-in as reachable, the KEK would go nowhere on every
    /// headless box.
    #[test]
    fn an_unreachable_store_still_writes_the_secret_to_disk() {
        let (store, file) = scratch("headless-write");
        store.store_to(&file, &never_claimed(&file), "a-secret", Custody::Unavailable(TEST_REASON), &no_store).expect("store must not error");
        assert_eq!(
            CredentialStore::load_file(&file).unwrap().as_deref(),
            Some("a-secret"),
            "with no reachable store the secret must be written to disk"
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Adoption is what deletes the file, so the case where there is nothing to adopt INTO must leave
    /// it alone. A headless launch of an install that already migrated on the desktop side would
    /// otherwise be a launch that removes the only copy it can still read.
    #[test]
    fn nothing_is_adopted_when_no_store_is_reachable() {
        let (store, file) = scratch("no-adopt");
        CredentialStore::store_file(&file, "leave-me-alone").unwrap();

        store.adopt_from_file("leave-me-alone", &file, &never_claimed(&file), Custody::Unavailable(TEST_REASON), &no_store);
        store.adopt_from_file("leave-me-alone", &file, &never_claimed(&file), Custody::NoStore, &no_store);

        assert_eq!(
            CredentialStore::load_file(&file).unwrap().as_deref(),
            Some("leave-me-alone"),
            "the file is the only custody here and must survive"
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Round-trips through the file half, since that is the path every headless Linux install takes.
    /// The operator's override beats every probe. A machine that CAN reach a store is not the same
    /// question as one that should use it, and the headless-Mac case is decided before the first
    /// adoption or not at all.
    #[test]
    fn an_operator_can_insist_on_the_file() {
        let _guard = CUSTODY_ENV.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("PERMAURA_VAULT_CUSTODY");

        std::env::set_var("PERMAURA_VAULT_CUSTODY", "file");
        // Asserted in EVERY feature configuration, not just one with a store compiled in. The first
        // version of this only ran where `apple-native` was on, which is how it passed on a Mac and
        // failed on the Linux lane where no backend is built at all.
        let custody = Custody::of(false, truthy_file_custody());
        assert!(!custody.is_native(), "an explicit file custody must never resolve to the OS store");
        let Custody::Unavailable(why) = custody else {
            panic!("the operator's instruction must outrank the capability probes, got {custody:?}")
        };
        assert!(why.contains("configured"), "the refusal must name the operator, not the machine: {why}");

        // Anything else is not an opt-out. A typo must not quietly weaken custody.
        for v in ["auto", "os", "", "FILES"] {
            std::env::set_var("PERMAURA_VAULT_CUSTODY", v);
            assert!(!truthy_file_custody(), "{v:?} must not read as file custody");
        }
        // Spelling and case are forgiven, since this is typed by hand into a config file.
        for v in ["file", "FILE", " File "] {
            std::env::set_var("PERMAURA_VAULT_CUSTODY", v);
            assert!(truthy_file_custody(), "{v:?} must read as file custody");
        }

        match prev {
            Some(v) => std::env::set_var("PERMAURA_VAULT_CUSTODY", v),
            None => std::env::remove_var("PERMAURA_VAULT_CUSTODY"),
        }
    }

    /// A shipped app's store keeps the platform store when its environment asks for the file, because any process running as the user can set that environment.
    #[test]
    fn a_shipped_build_keeps_an_app_store_out_of_the_file() {
        let (app, _file) = scratch("release-app-store");
        let platform = Custody::of(app.needs_stable_code_identity, false);
        let reported = AtomicBool::new(false);
        let custody = with_custody_env("PERMAURA_VAULT_CUSTODY", "file".as_ref(), || app.custody(false, &reported));
        assert_eq!(custody, platform, "a release build must ignore PERMAURA_VAULT_CUSTODY for a store that does not opt in");
        assert!(
            !matches!(custody, Custody::Unavailable(why) if why.contains("configured")),
            "the operator's file custody must not reach an app's store in a release build"
        );
        assert!(reported.load(Ordering::Relaxed), "an ignored override must be reported");
    }

    /// The gateway's documented file custody keeps working in a release build, and a debug build honors it for every store.
    #[test]
    fn a_server_store_and_a_debug_build_still_honor_file_custody() {
        let (app, _file) = scratch("release-server-store");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let reported = AtomicBool::new(false);
        let (server_release, app_debug) = with_custody_env("PERMAURA_VAULT_CUSTODY", "file".as_ref(), || {
            (server.custody(false, &reported), app.custody(true, &reported))
        });
        for (who, custody) in [("a server store in a release build", server_release), ("an app store in a debug build", app_debug)] {
            let Custody::Unavailable(why) = custody else { panic!("{who} must honor PERMAURA_VAULT_CUSTODY=file, got {custody:?}") };
            assert!(why.contains("configured"), "{who}: {why}");
        }
        assert!(!reported.load(Ordering::Relaxed), "nothing was ignored, so nothing is reported");
    }

    /// A shipped app's store does not take a secret from a directory its environment names, while the gateway under systemd still does.
    #[test]
    fn a_shipped_build_reads_a_systemd_credential_only_for_a_server_store() {
        let (app, file) = scratch("release-systemd-credential");
        let dir = file.parent().expect("scratch dir").join("credentials");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(app.account), "planted\n").unwrap();
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let reported = AtomicBool::new(false);
        let (app_release, server_release, app_debug) = with_custody_env("CREDENTIALS_DIRECTORY", dir.as_os_str(), || {
            (
                app.systemd_credential_in(false, &reported),
                server.systemd_credential_in(false, &reported),
                app.systemd_credential_in(true, &reported),
            )
        });
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(app_release, None, "a release app store must ignore CREDENTIALS_DIRECTORY");
        assert_eq!(server_release.as_deref(), Some("planted"), "the gateway's systemd custody must keep working");
        assert_eq!(app_debug.as_deref(), Some("planted"), "a debug build honors it for every store");
        assert!(reported.load(Ordering::Relaxed), "an ignored override must be reported");
    }

    /// An OS store held by the test, so the paths that write to the store and read it back run against something other than this machine's Keychain.
    ///
    /// Each item records who added it, standing in for the access list a Keychain item keeps: a write into an item keeps it, and only an add sets it.
    #[derive(Clone, Default)]
    struct TestKeychain {
        held: std::sync::Arc<std::sync::Mutex<Option<TestItem>>>,
        refuses_writes: bool,
        refuses_deletes: bool,
        /// A value another program adds the moment an item is removed.
        replants: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        /// The login keychain cannot be found or opened, the way `login_keychain` reports it.
        no_login_keychain: bool,
        /// A removal reports success and leaves the item, as the Keychain's unreported delete can.
        removal_does_not_take: bool,
        /// A file another program writes, with its value, while the store is being read.
        writes_file_on_read: std::sync::Arc<std::sync::Mutex<Option<(std::path::PathBuf, String)>>>,
        /// Writes are refused the way the data-protection keychain refuses a build without its access group.
        data_protection_refuses: bool,
        /// Writes are refused as too long, the way Credential Manager refuses a blob over its limit.
        too_long: bool,
    }

    #[derive(Clone)]
    struct TestItem {
        secret: String,
        added_by: AddedBy,
    }

    /// Whose access list an item carries.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AddedBy {
        TheApp,
        AnotherProgram,
    }

    impl TestKeychain {
        fn with_item(secret: &str, added_by: AddedBy) -> Self {
            let keychain = Self::default();
            *keychain.held.lock().unwrap() = Some(TestItem { secret: secret.to_string(), added_by });
            keychain
        }

        fn holding(secret: &str) -> Self {
            Self::with_item(secret, AddedBy::TheApp)
        }

        fn planted(secret: &str) -> Self {
            Self::with_item(secret, AddedBy::AnotherProgram)
        }

        fn held(&self) -> Option<String> {
            self.held.lock().unwrap().as_ref().map(|item| item.secret.clone())
        }

        fn added_by(&self) -> Option<AddedBy> {
            self.held.lock().unwrap().as_ref().map(|item| item.added_by)
        }

        fn open(&self) -> impl Fn(&str) -> Result<Entry, String> + '_ {
            |_| Ok(Entry::new_with_credential(Box::new(self.clone())))
        }

        /// The Keychain's add: refuses an item already there.
        fn add(&self, secret: &str) -> Result<(), AddRefused> {
            if self.no_login_keychain {
                return Err(AddRefused::NoLoginKeychain(no_login_keychain_in_the_test()));
            }
            let mut held = self.held.lock().unwrap();
            if held.is_some() {
                return Err(AddRefused::Occupied);
            }
            if self.refuses_writes {
                return Err(AddRefused::Failed("refused by the test".into()));
            }
            *held = Some(TestItem { secret: secret.to_string(), added_by: AddedBy::TheApp });
            Ok(())
        }

        fn add_own(&self) -> impl Fn(&Entry, &str) -> Result<(), AddRefused> + '_ {
            |_, secret| self.add(secret)
        }
    }

    /// The refusal a test's login keychain gives when it cannot be found.
    fn no_login_keychain_in_the_test() -> NoLoginKeychain {
        NoLoginKeychain("/Users/someone/Library/Keychains/login.keychain-db could not be read: gone in the test".into())
    }

    impl keyring::credential::CredentialApi for TestKeychain {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            if self.no_login_keychain {
                return Err(no_login_keychain_in_the_test().into());
            }
            if self.data_protection_refuses {
                return Err(DataProtectionRefused("missing entitlement, in the test".into()).into());
            }
            if self.refuses_writes {
                return Err(keyring::Error::NoStorageAccess("refused by the test".into()));
            }
            if self.too_long {
                return Err(keyring::Error::TooLong("password".into(), 2560));
            }
            let secret = String::from_utf8(secret.to_vec()).expect("utf-8");
            let mut held = self.held.lock().unwrap();
            let added_by = held.as_ref().map_or(AddedBy::TheApp, |item| item.added_by);
            *held = Some(TestItem { secret, added_by });
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            if self.no_login_keychain {
                return Err(no_login_keychain_in_the_test().into());
            }
            if let Some((file, value)) = self.writes_file_on_read.lock().unwrap().take() {
                CredentialStore::store_file(&file, &value).expect("the test's write-back");
            }
            self.held().map(String::into_bytes).ok_or(keyring::Error::NoEntry)
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            if self.no_login_keychain {
                return Err(no_login_keychain_in_the_test().into());
            }
            if self.refuses_deletes {
                return Err(keyring::Error::NoStorageAccess("refused by the test".into()));
            }
            let mut held = self.held.lock().unwrap();
            if self.removal_does_not_take {
                return held.as_ref().map(|_| ()).ok_or(keyring::Error::NoEntry);
            }
            let removed = held.take().map(|_| ()).ok_or(keyring::Error::NoEntry);
            if let Some(secret) = self.replants.lock().unwrap().take() {
                *held = Some(TestItem { secret, added_by: AddedBy::AnotherProgram });
            }
            removed
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A value the store can never hold (on Windows, one too long for Credential Manager, which the desktop's audience pins outgrow at the seventh hosted gateway) is refused to the caller, writing nothing: in the owner-only file it would be undone by the next load the store answers, which prefers the older item and removes the file, so every such write would be lost and look stored. A refusal that may pass keeps the documented file fallback.
    #[test]
    fn a_value_the_store_can_never_hold_is_refused_rather_than_lost_to_the_older_item() {
        let (store, file) = scratch("routine-too-long");
        let marker = claimed(&file);
        let keychain = TestKeychain { too_long: true, ..TestKeychain::holding("six-gateway-pins") };
        let err = store
            .store_to(&file, &marker, "seven-gateway-pins", Custody::Native, &keychain.open())
            .expect_err("a value the store cannot hold must be refused, not parked where the next load discards it");
        assert!(err.to_string().contains("was not written"), "{err}");
        assert!(err.to_string().contains("too long"), "the store's reason survives: {err}");
        assert!(!file.exists(), "nothing was written anywhere in its place");
        assert!(marker.exists(), "the marker still names the store, which still holds the earlier value");
        assert_eq!(keychain.held().as_deref(), Some("six-gateway-pins"));
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()), Ok(Some("six-gateway-pins".into())));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A program running as this user can write the file beside a populated store. Taking the file would replace the paired approver key, the audience pins or the session with values that program chose, so the store's copy wins and the file is removed.
    #[test]
    fn an_app_store_keeps_its_own_copy_over_a_planted_file_and_removes_the_file() {
        let (store, file) = scratch("planted-file");
        let keychain = TestKeychain::holding("the-paired-approver-key");
        let marker = claimed(&file);
        CredentialStore::store_file(&file, "a-key-the-planting-program-knows").unwrap();

        let loaded = store.load_from(&file, &marker, Custody::Native, &keychain.open()).expect("the store's copy must be read, not refused");

        assert_eq!(loaded.as_deref(), Some("the-paired-approver-key"));
        assert_eq!(keychain.held().as_deref(), Some("the-paired-approver-key"), "a planted file must never be adopted over the store");
        assert!(!file.exists(), "the planted file must be removed");
        assert!(marker.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An earlier build's store write left the older file beside the newer stored copy (a sign-in after an ignored file custody, or a fallback write followed by a store write). Taking the file there would throw away the newer sign-in for an older session, possibly another account's.
    #[test]
    fn an_app_store_keeps_the_newer_store_copy_over_an_older_file() {
        let (store, file) = scratch("older-file");
        let keychain = TestKeychain::holding("K2-newer-sign-in");
        CredentialStore::store_file(&file, "F1-older-session").unwrap();
        let marker = never_claimed(&file);

        let loaded = store.load_from(&file, &marker, Custody::Native, &keychain.open()).unwrap();

        assert_eq!(loaded.as_deref(), Some("K2-newer-sign-in"));
        assert_eq!(keychain.held().as_deref(), Some("K2-newer-sign-in"));
        assert!(!file.exists(), "the stale plaintext copy must not survive the read");
        assert!(marker.exists(), "with the file gone, the marker is what stops a later launch that cannot reach the store from calling it a first run");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The file is removed only once the marker records the store, so an unwritable marker leaves the file in place while the store's copy is still the one returned.
    #[test]
    fn an_app_store_keeps_the_file_when_the_marker_cannot_be_written() {
        let (store, file) = scratch("marker-blocked");
        let keychain = TestKeychain::holding("in-the-store");
        CredentialStore::store_file(&file, "on-disk").unwrap();
        let blocker = file.with_file_name("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();
        let marker = blocker.join("marker");

        let loaded = store.load_from(&file, &marker, Custody::Native, &keychain.open()).unwrap();

        assert_eq!(loaded.as_deref(), Some("in-the-store"));
        assert_eq!(keychain.held().as_deref(), Some("in-the-store"));
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("on-disk"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Signing in again over a store and file that disagree writes the store, and the stale plaintext file must not survive it.
    #[test]
    fn an_app_store_sign_in_leaves_no_file_behind() {
        let (store, file) = scratch("victim-sign-in");
        let keychain = TestKeychain::holding("refresh-token-before-the-setenv");
        CredentialStore::store_file(&file, "refresh-token-rotated-under-file-custody").unwrap();
        let marker = never_claimed(&file);

        store.store_to(&file, &marker, "refresh-token-from-signing-in-again", Custody::Native, &keychain.open()).expect("a sign-in must store");

        assert_eq!(keychain.held().as_deref(), Some("refresh-token-from-signing-in-again"));
        assert!(!file.exists(), "a native write must not leave an older plaintext copy behind");
        assert_eq!(
            store.load_from(&file, &marker, Custody::Native, &keychain.open()).unwrap().as_deref(),
            Some("refresh-token-from-signing-in-again"),
            "the next read must see the sign-in"
        );
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A sign-in the store took has succeeded even when the leftover file cannot be removed, since every read prefers the store's copy and retries the removal.
    #[test]
    fn an_app_store_write_stands_when_the_leftover_file_cannot_be_removed() {
        let (store, file) = scratch("unremovable-file");
        let keychain = TestKeychain::holding("before");
        std::fs::create_dir_all(file.join("occupied")).unwrap();
        let marker = never_claimed(&file);

        store.store_to(&file, &marker, "signed-in", Custody::Native, &keychain.open()).expect("the store holds the sign-in");

        assert_eq!(keychain.held().as_deref(), Some("signed-in"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The gateway's vault KEK keeps today's behavior: its operator can set file custody, so a store and file that disagree are two keys of which only one sealed the vault, and the read refuses rather than guess, and a store write leaves the file alone.
    #[test]
    fn a_server_store_still_refuses_a_store_and_file_that_disagree() {
        let (app, file) = scratch("server-disagree");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let keychain = TestKeychain::holding("kek-in-the-keychain");
        CredentialStore::store_file(&file, "kek-in-the-file").unwrap();
        let marker = never_claimed(&file);

        let err = server.load_from(&file, &marker, Custody::Native, &keychain.open()).expect_err("a server store must not pick one of two keys");
        assert!(err.contains("do not match"), "{err}");
        assert_eq!(keychain.held().as_deref(), Some("kek-in-the-keychain"), "nothing may be adopted over the store");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("kek-in-the-file"), "nothing may be removed");

        server.store_to(&file, &marker, "kek-written-to-the-keychain", Custody::Native, &keychain.open()).unwrap();
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("kek-in-the-file"), "a server store write leaves the file as it always has");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Another program writes the owner-only file while the store is being asked, after the caller removed it, and the store holds no item: `load` adopts that file, the file-free load reads it as no file at all.
    #[test]
    fn a_file_free_load_neither_returns_nor_adopts_a_file_beside_no_item() {
        let (store, file) = scratch("file-free-write-back");
        let marker = never_claimed(&file);
        let planted = "a-key-the-planting-program-knows";
        let writing_back = || {
            std::fs::remove_file(&file).ok();
            let keychain = TestKeychain::default();
            *keychain.writes_file_on_read.lock().unwrap() = Some((file.clone(), planted.to_string()));
            keychain
        };

        let adopting = writing_back();
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &adopting.open()).unwrap().as_deref(), Some(planted), "precondition: load adopts the write-back");
        assert_eq!(adopting.held().as_deref(), Some(planted));
        std::fs::remove_file(&marker).unwrap();

        let keychain = writing_back();
        let loaded = store.load_in(&file, &marker, Custody::Native, &keychain.open(), FileRead::Skipped);

        assert_eq!(loaded, Ok(None), "a file beside no item must read as nothing stored");
        assert_eq!(keychain.held(), None, "the file must not be adopted into the store");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some(planted), "the read path leaves the file as it was written");
        assert!(!marker.exists(), "nothing reached the store, so nothing may claim it");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The file-free load still returns a stored item, and still removes a file beside it unread once the store is claimed, as `load` does.
    #[test]
    fn a_file_free_load_returns_the_stored_item_and_removes_a_file_beside_it() {
        let (store, file) = scratch("file-free-item");
        let keychain = TestKeychain::holding("the-paired-approver-key");
        let marker = never_claimed(&file);
        assert_eq!(
            store.load_in(&file, &marker, Custody::Native, &keychain.open(), FileRead::Skipped).unwrap().as_deref(),
            Some("the-paired-approver-key")
        );

        CredentialStore::store_file(&file, "a-key-the-planting-program-knows").unwrap();
        let loaded = store.load_in(&file, &marker, Custody::Native, &keychain.open(), FileRead::Skipped).unwrap();

        assert_eq!(loaded.as_deref(), Some("the-paired-approver-key"));
        assert_eq!(keychain.held().as_deref(), Some("the-paired-approver-key"));
        assert!(!file.exists(), "a file beside a stored item is removed");
        assert!(marker.exists(), "the store is claimed before the file goes");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The file-free load answers every arm of the table as `load` does where no file stands, whatever stands there: with the marker a store that returns nothing is a refusal, never a first run, and without it a first run, never the file.
    #[test]
    fn a_file_free_load_answers_every_arm_as_load_does_with_no_file() {
        let (store, file) = scratch("file-free-arms");
        let no_file = file.with_file_name("no-file-stands-here");
        CredentialStore::store_file(&file, "on-disk").unwrap();
        let arms = || {
            [
                Native::Empty,
                Native::NoStore,
                Native::Unavailable(TEST_REASON),
                Native::Failed("the keyring is locked".into()),
                Native::Found("in-the-store".into()),
            ]
        };
        let sysm = file.with_file_name("never-written.in-systemd-credential");
        for claimed_by_store in [false, true] {
            let marker = if claimed_by_store { claimed(&file) } else { never_claimed(&file) };
            for (skipping, asking) in arms().into_iter().zip(arms()) {
                let arm = format!("{:?}", store.decide_with(None, asking, &no_file, &marker, &sysm, FileRead::Asked));
                let skipped = store.decide_with(None, skipping, &file, &marker, &sysm, FileRead::Skipped);
                assert_eq!(format!("{skipped:?}"), arm, "claimed by the store: {claimed_by_store}");
                match &skipped {
                    Ok(Source::Native(_)) => {}
                    Ok(source) => assert!(!claimed_by_store && *source == Source::Absent, "{source:?}"),
                    Err(e) => assert!(claimed_by_store && e.contains("Refusing to mint"), "{e}"),
                }
            }
        }
        assert!(!sysm.exists());

        let provisioned = file.with_file_name("provisioned.in-systemd-credential");
        let marker = never_claimed(&file);
        assert_eq!(
            store.decide_with(Some("from-the-tpm".into()), Native::Empty, &file, &marker, &provisioned, FileRead::Skipped),
            Ok(Source::SystemdCredential("from-the-tpm".into())),
            "a file that is never read cannot disagree with a provisioned credential"
        );
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("on-disk"), "the read path leaves the file as it found it");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The public file-free load is `load` with the file skipped, here on a store whose custody is the file, which opens no store in any profile.
    #[test]
    fn load_without_file_is_load_with_the_file_treated_as_absent() {
        let (app, file) = scratch("file-free-public");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let home = file.parent().expect("scratch dir").join("home");
        std::fs::create_dir_all(&home).unwrap();
        let (without, with) = with_home(&home, || {
            CredentialStore::store_file(&server.path().unwrap(), "in-the-file").unwrap();
            with_custody_env("PERMAURA_VAULT_CUSTODY", "file".as_ref(), || (server.load_without_file(), server.load()))
        });
        assert_eq!(without, Ok(None));
        assert_eq!(with.unwrap().as_deref(), Some("in-the-file"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// Another program created the item before the sign-in, with an access list that admits itself; the sign-in's fresh write must leave an item the app added, holding the new session, so that program reads none of what follows.
    #[test]
    fn a_fresh_write_replaces_a_planted_item_with_one_the_app_added() {
        let (store, file) = scratch("fresh-over-planted");
        let keychain = TestKeychain::planted("a-session-the-planting-program-chose");
        let marker = never_claimed(&file);

        store
            .store_fresh_to(&file, &marker, "the-new-sign-in", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect("a sign-in over a planted item must store");

        assert_eq!(keychain.held().as_deref(), Some("the-new-sign-in"));
        assert_eq!(keychain.added_by(), Some(AddedBy::TheApp), "the new session must not sit in an item another program added");
        assert!(marker.exists(), "the store holds the secret, so the marker must say so");
        assert!(!file.exists());
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()).unwrap().as_deref(), Some("the-new-sign-in"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A routine write (a refresh rotation, a later pin) keeps writing in place, as 1.3.52 did: removing the item first would put a value the user relies on through an interruption window.
    #[test]
    fn a_routine_write_still_writes_into_the_item_it_finds() {
        let (store, file) = scratch("routine-in-place");
        let keychain = TestKeychain::holding("refresh-token-1");
        let marker = claimed(&file);

        store.store_to(&file, &marker, "refresh-token-2", Custody::Native, &keychain.open()).unwrap();

        assert_eq!(keychain.held().as_deref(), Some("refresh-token-2"));
        assert_eq!(keychain.added_by(), Some(AddedBy::TheApp));
        assert!(marker.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The window the earlier design lost secrets in. A fresh write interrupted between removing the item and adding its own (a quit, a crash, an updater relaunch), with no owner-only file beside it, must leave a state the next launch reads as nothing stored, a sign-in or a pairing to repeat, not a refusal over a store that lost what the marker claims.
    #[test]
    fn a_fresh_write_interrupted_after_the_removal_reads_as_nothing_stored() {
        let (store, file) = scratch("fresh-interrupted");
        let keychain = TestKeychain::holding("the-session-being-replaced");
        let marker = claimed(&file);
        let at_the_add = std::cell::RefCell::new(None);
        let add_after_a_look = |_: &Entry, secret: &str| {
            *at_the_add.borrow_mut() = Some(store.load_from(&file, &marker, Custody::Native, &keychain.open()));
            keychain.add(secret)
        };

        store
            .store_fresh_to(&file, &marker, "the-new-session", Custody::Native, &keychain.open(), Some(&add_after_a_look))
            .unwrap();

        let seen = at_the_add.into_inner().expect("the add ran");
        assert_eq!(seen, Ok(None), "a launch after an interruption there must read nothing stored, not refuse");
        assert_eq!(keychain.held().as_deref(), Some("the-new-session"));
        assert!(marker.exists(), "a completed fresh write claims the store again");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The same interruption over an owner-only file an earlier refused write left: the next load returns that write's value, the user's own, and moves it back into the store, rather than reading nothing stored or refusing.
    #[test]
    fn a_fresh_write_interrupted_after_the_removal_reads_the_file_an_earlier_refused_write_left() {
        let (store, file) = scratch("fresh-interrupted-file");
        let keychain = TestKeychain::holding("v0-the-session-before");
        let marker = claimed(&file);
        let refusing = TestKeychain { refuses_writes: true, ..keychain.clone() };
        store.store_to(&file, &marker, "v1-the-refused-write", Custody::Native, &refusing.open()).unwrap();
        assert!(!marker.exists() && file.exists(), "a refused write leaves the owner-only file and no marker");

        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let never_reached = |_: &Entry, _: &str| -> Result<(), AddRefused> { panic!("the app stops before the add") };
            store.store_fresh_to(&file, &marker, "v2-the-new-session", Custody::Native, &keychain.open(), Some(&never_reached))
        }));
        assert!(interrupted.is_err());
        assert_eq!(keychain.held(), None, "the interruption leaves the item removed");

        let seen = store.load_from(&file, &marker, Custody::Native, &keychain.open());
        assert_eq!(seen, Ok(Some("v1-the-refused-write".to_string())), "the next load reads the file, not nothing stored and not a refusal");
        assert_eq!(keychain.held().as_deref(), Some("v1-the-refused-write"), "the file's value is moved back into the store");
        assert!(marker.exists());
        assert!(!file.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An item another program puts back between the removal and the add is refused by the add, and the fresh write fails rather than writing the new session into it or into a plaintext file.
    #[test]
    fn a_fresh_write_writes_nothing_into_an_item_planted_after_its_removal() {
        let (store, file) = scratch("fresh-replanted");
        let keychain = TestKeychain::holding("the-session-being-replaced");
        *keychain.replants.lock().unwrap() = Some("planted-in-the-window".into());
        let marker = claimed(&file);

        let err = store
            .store_fresh_to(&file, &marker, "the-new-session", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("a re-planted item must fail the fresh write");

        let StoreFreshError::Occupied(why) = &err else { panic!("a re-planted item is the Occupied refusal, got {err:?}") };
        assert!(why.contains("nothing was written into that item"), "{why}");
        assert!(why.contains(store.service) && why.contains(store.account) && why.contains("Keychain Access"), "the refusal must name the item and the remedy: {why}");
        assert_eq!(keychain.held().as_deref(), Some("planted-in-the-window"), "nothing may be written into the planted item");
        assert_eq!(keychain.added_by(), Some(AddedBy::AnotherProgram));
        assert!(!file.exists(), "the new session must not land in a plaintext file either");
        assert!(marker.exists(), "the marker is left as the write found it, since nothing can tell whose item stands");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A standing item the fresh write cannot remove is left as it was, marker included, and nothing is written into it.
    #[test]
    fn a_fresh_write_that_cannot_remove_the_standing_item_changes_nothing() {
        let (store, file) = scratch("fresh-undeletable");
        let keychain = TestKeychain { refuses_deletes: true, ..TestKeychain::planted("a-standing-item") };
        let marker = claimed(&file);

        let err = store
            .store_fresh_to(&file, &marker, "the-new-key", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("an item that cannot be removed must fail the fresh write");

        let StoreFreshError::Failed(why) = &err else { panic!("a refused removal is not an Occupied refusal, got {err:?}") };
        assert!(why.contains("could not be removed"), "{why}");
        assert!(why.contains("refused by the test"), "the store's own reason must survive: {why}");
        assert!(why.contains(store.service) && why.contains(store.account) && why.contains("Keychain Access"), "the refusal must name the item and the remedy: {why}");
        assert_eq!(keychain.held().as_deref(), Some("a-standing-item"));
        assert!(marker.exists(), "the marker must be put back over a store that still holds the item");
        assert!(!file.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A program that makes the login keychain refuse the add (an unwritable keychain file) must not divert a new sign-in, approver key or pin into the owner-only file, where it stays the live copy: the fresh write fails with nothing written, reads afterwards as an interrupted one does, and a routine write still falls back to the file.
    #[test]
    fn a_fresh_write_the_store_refuses_fails_and_writes_no_file() {
        let (store, file) = scratch("fresh-refused");
        let keychain = TestKeychain { refuses_writes: true, ..TestKeychain::holding("the-key-being-replaced") };
        let marker = claimed(&file);

        let err = store
            .store_fresh_to(&file, &marker, "the-new-key", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("a refused add must fail the fresh write");

        let StoreFreshError::Failed(why) = &err else { panic!("a refused add is the Failed refusal, got {err:?}") };
        assert!(why.contains("refused by the test") && why.contains("nothing was written anywhere"), "{why}");
        assert!(why.contains(store.service) && why.contains(store.account) && why.contains("Keychain Access"), "the refusal must name the item and the remedy: {why}");
        assert!(!file.exists(), "the new secret must not land in the owner-only file");
        assert_eq!(keychain.held(), None);
        assert!(!marker.exists(), "the item was removed, so as after an interruption at the add the next load reads nothing stored rather than refusing");
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()), Ok(None));

        CredentialStore::store_file(&file, "an-earlier-routine-write").unwrap();
        store
            .store_fresh_to(&file, &marker, "the-new-key", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("a refused add must fail the fresh write");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("an-earlier-routine-write"), "a file an earlier routine write left is not overwritten");

        store.store_to(&file, &marker, "a-refresh-rotation", Custody::Native, &keychain.open()).expect("a routine write still takes the file");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("a-refresh-rotation"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A routine write the store refuses leaves the rotation in the owner-only file and the earlier session in the item: a load the store does not answer returns the rotation and keeps the file, and the first load it answers returns the earlier session and removes the file.
    #[test]
    fn a_refused_routine_write_is_read_from_the_file_until_the_store_answers_and_then_the_earlier_item_wins() {
        let (store, file) = scratch("routine-refused-then-answered");
        let marker = claimed(&file);
        let keychain = TestKeychain { refuses_writes: true, ..TestKeychain::holding("session-r1") };
        store.store_to(&file, &marker, "session-r2", Custody::Native, &keychain.open()).expect("a routine write falls back to the file");
        assert_eq!(keychain.held().as_deref(), Some("session-r1"));
        assert!(!marker.exists());

        let locked = |_: &str| -> Result<Entry, String> { Err("the login keychain is locked".into()) };
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &locked), Ok(Some("session-r2".into())));
        assert!(file.exists(), "a store that cannot be read takes no adoption either");
        assert_eq!(keychain.held().as_deref(), Some("session-r1"));

        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()), Ok(Some("session-r1".into())));
        assert!(!file.exists() && marker.exists());
        assert_eq!(keychain.held().as_deref(), Some("session-r1"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A refused routine write's rotation reaches the item through a load whose read the store fails and whose write of the file's value it then takes.
    #[test]
    fn a_load_whose_read_fails_and_whose_write_lands_moves_a_refused_rotation_into_the_item() {
        let (store, file) = scratch("routine-refused-then-adopted");
        let marker = claimed(&file);
        let keychain = TestKeychain::holding("session-r1");
        let refusing = TestKeychain { refuses_writes: true, ..keychain.clone() };
        store.store_to(&file, &marker, "session-r2", Custody::Native, &refusing.open()).expect("a routine write falls back to the file");

        let opens = std::cell::Cell::new(0);
        let read_fails_then_write_lands = |account: &str| {
            opens.set(opens.get() + 1);
            if opens.get() == 1 { Err("the login keychain is locked".to_string()) } else { keychain.open()(account) }
        };
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &read_fails_then_write_lands), Ok(Some("session-r2".into())));
        assert_eq!(keychain.held().as_deref(), Some("session-r2"));
        assert!(!file.exists() && marker.exists());

        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()), Ok(Some("session-r2".into())));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An app store's fresh write never takes the owner-only file, even when its entry cannot be opened; a server store's still does, as its routine write always has.
    #[test]
    fn a_fresh_write_whose_entry_cannot_be_opened_writes_no_file_for_an_app_store() {
        let (app, file) = scratch("fresh-unopenable");
        let marker = claimed(&file);
        let keychain = TestKeychain::default();

        let err = app
            .store_fresh_to(&file, &marker, "the-new-key", Custody::Native, &no_store, Some(&keychain.add_own()))
            .expect_err("an entry that cannot be opened must fail the fresh write");
        assert!(matches!(&err, StoreFreshError::Failed(why) if why.contains("this test opens no OS credential store") && why.contains(app.service)), "{err:?}");
        assert!(!file.exists(), "the new secret must not land in the owner-only file");
        assert!(marker.exists(), "nothing was removed, so the marker stands");

        let server = CredentialStore { operator_sets_custody: true, ..app };
        server
            .store_fresh_to(&file, &marker, "kek-written", Custody::Native, &no_store, Some(&keychain.add_own()))
            .expect("a server store's write falls back to the file");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("kek-written"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The gateway's vault KEK, a build with no per-item access list (Windows, Linux) and a launch with no store all write a fresh secret exactly as they write any other.
    #[test]
    fn a_fresh_write_is_a_routine_one_for_a_server_store_and_where_items_have_no_access_list() {
        let (app, file) = scratch("fresh-is-routine");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let marker = never_claimed(&file);

        let keychain = TestKeychain::planted("kek-in-the-keychain");
        CredentialStore::store_file(&file, "kek-in-the-file").unwrap();
        server
            .store_fresh_to(&file, &marker, "kek-written", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .unwrap();
        assert_eq!(keychain.held().as_deref(), Some("kek-written"));
        assert_eq!(keychain.added_by(), Some(AddedBy::AnotherProgram), "a server store writes in place");
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("kek-in-the-file"), "and leaves the file as it always has");

        let keychain = TestKeychain::planted("a-credential-manager-item");
        app.store_fresh_to(&file, &marker, "a-new-session", Custody::Native, &keychain.open(), None).unwrap();
        assert_eq!(keychain.held().as_deref(), Some("a-new-session"));
        assert_eq!(keychain.added_by(), Some(AddedBy::AnotherProgram), "with no access list to replace, the write is in place");

        let keychain = TestKeychain::holding("untouched");
        app.store_fresh_to(&file, &marker, "into-the-file", Custody::NoStore, &keychain.open(), Some(&keychain.add_own())).unwrap();
        assert_eq!(keychain.held().as_deref(), Some("untouched"));
        assert_eq!(CredentialStore::load_file(&file).unwrap().as_deref(), Some("into-the-file"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A fresh write that is a routine one (a server store, a build with no per-item access list, a launch with no store, a debug build told to keep the file) reports an owner-only file it could not write as Failed, naming the file, and leaves the store's item as it was.
    #[test]
    fn a_routine_fresh_write_whose_owner_only_file_cannot_be_written_is_failed() {
        let (app, file) = scratch("fresh-routine-file-fails");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let dir = file.parent().expect("scratch dir").to_path_buf();
        let not_a_directory = dir.join("not-a-directory");
        std::fs::write(&not_a_directory, "").unwrap();
        let unwritable = not_a_directory.join("secret");
        let marker = dir.join("secret.in-os-store");
        let keychain = TestKeychain { refuses_writes: true, ..TestKeychain::holding("the-secret-before") };
        let add = keychain.add_own();

        let results = [
            ("a server store", server.store_fresh_to(&unwritable, &marker, "new", Custody::Native, &keychain.open(), Some(&add))),
            ("an app store off the Keychain build", app.store_fresh_to(&unwritable, &marker, "new", Custody::Native, &keychain.open(), None)),
            ("an app store with no store", app.store_fresh_to(&unwritable, &marker, "new", Custody::NoStore, &keychain.open(), Some(&add))),
            ("an app store told to keep the file", app.store_fresh_to(&unwritable, &marker, "new", Custody::of(false, true), &keychain.open(), Some(&add))),
        ];

        for (who, result) in results {
            let Err(StoreFreshError::Failed(why)) = &result else { panic!("{who}: got {result:?}") };
            assert!(why.contains(&unwritable.display().to_string()), "{who}: the refusal must name the file: {why}");
        }
        assert_eq!(keychain.held().as_deref(), Some("the-secret-before"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Only the macOS Keychain gives an item an access list of its own, so only a build that reaches it has a fresh write of its own; Windows and Linux keep their 1.3.52 write.
    #[test]
    fn only_a_keychain_build_has_a_fresh_write_of_its_own() {
        assert_eq!(own_item_add().is_some(), cfg!(all(target_os = "macos", feature = "apple-native")));
    }

    /// The Keychain's duplicate-item refusal is what fails a fresh write over a re-planted item, a keychain that is missing or is not one is the login keychain's refusal, and anything else the add refuses is an ordinary refusal; no check opens the Keychain.
    #[cfg(all(target_os = "macos", feature = "apple-native"))]
    #[test]
    fn a_duplicate_keychain_add_is_an_occupied_name() {
        use security_framework::base::Error;
        assert_eq!(keychain_add_refusal(Error::from_code(-25299)), AddRefused::Occupied);
        assert!(matches!(keychain_add_refusal(Error::from_code(-25308)), AddRefused::Failed(_)));
        for no_keychain in [-25294, -25295] {
            assert!(matches!(keychain_add_refusal(Error::from_code(no_keychain)), AddRefused::NoLoginKeychain(_)), "{no_keychain}");
        }
        let not_a_keychain_item = Entry::new_with_credential(Box::new(keyring::mock::MockCredential::default()));
        assert!(matches!(add_keychain_item(&not_a_keychain_item, "x"), Err(AddRefused::Failed(_))));
    }

    /// An app store's every read, removal, write and add goes to the login keychain by path, never through keyring's user-domain default, which another program can repoint; the gateway's vault KEK keeps keyring's entry. Opening an entry touches no keychain.
    #[cfg(all(target_os = "macos", feature = "apple-native"))]
    #[test]
    fn an_app_store_addresses_the_login_keychain_and_a_server_store_keeps_keyrings_default() {
        use keyring::macos::MacCredential;
        let (app, _file) = scratch("login-keychain-entry");
        let entry = app.entry_named("login-keychain-entry").expect("an entry opens without a keychain");
        assert!(entry.get_credential().downcast_ref::<MacCredential>().is_none(), "an app store must not reach the user-domain default keychain");
        assert!(entry.get_credential().downcast_ref::<login_keychain::LoginKeychainItem>().is_some());

        let server = CredentialStore { operator_sets_custody: true, ..app };
        let entry = server.entry_named("login-keychain-entry").expect("an entry opens without a keychain");
        assert!(entry.get_credential().downcast_ref::<MacCredential>().is_some(), "the vault KEK keeps its 1.3.53 store");
    }

    /// A routine write whose login keychain cannot be found or opened fails, and writes neither another keychain nor the owner-only file; the secret already stored is untouched, and the next read refuses rather than reporting nothing stored.
    #[test]
    fn a_routine_write_fails_closed_when_the_login_keychain_cannot_be_opened() {
        let (store, file) = scratch("routine-no-login-keychain");
        let keychain = TestKeychain { no_login_keychain: true, ..TestKeychain::holding("refresh-token-1") };
        let marker = claimed(&file);

        let err = store
            .store_to(&file, &marker, "refresh-token-2", Custody::Native, &keychain.open())
            .expect_err("a write with no login keychain must fail");

        let StoreFreshError::LoginKeychainUnavailable(why) = &err else { panic!("got {err:?}") };
        assert!(why.contains("login keychain") && why.contains("gone in the test"), "{why}");
        assert!(why.contains(store.service) && why.contains(store.account) && why.contains("Keychain Access"), "{why}");
        assert!(!file.exists(), "the secret must not fall back to the owner-only file");
        assert!(marker.exists(), "the store may still hold the secret, so its marker stays");
        assert_eq!(keychain.held().as_deref(), Some("refresh-token-1"));
        let read = store.load_from(&file, &marker, Custody::Native, &keychain.open());
        assert!(read.as_ref().is_err_and(|e| e.contains("Refusing to mint")), "a read must not report nothing stored: {read:?}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A fresh write meets a missing login keychain at the removal, or at the add when it vanishes in between; either way it fails with nothing written anywhere and the marker as it found it.
    #[test]
    fn a_fresh_write_fails_closed_when_the_login_keychain_cannot_be_opened() {
        let (store, file) = scratch("fresh-no-login-keychain");
        let marker = claimed(&file);

        let keychain = TestKeychain { no_login_keychain: true, ..TestKeychain::holding("the-session-before") };
        let err = store
            .store_fresh_to(&file, &marker, "the-new-session", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("a fresh write with no login keychain must fail");
        assert!(matches!(&err, StoreFreshError::LoginKeychainUnavailable(why) if why.contains("Keychain Access")), "{err:?}");
        assert_eq!(keychain.held().as_deref(), Some("the-session-before"));
        assert!(marker.exists() && !file.exists());

        let keychain = TestKeychain::holding("the-session-before");
        let gone_by_the_add = |_: &Entry, _: &str| Err(AddRefused::NoLoginKeychain(no_login_keychain_in_the_test()));
        let err = store
            .store_fresh_to(&file, &marker, "the-new-session", Custody::Native, &keychain.open(), Some(&gone_by_the_add))
            .expect_err("a login keychain gone by the add must fail the fresh write");
        assert!(matches!(&err, StoreFreshError::LoginKeychainUnavailable(why) if why.contains(store.service)), "{err:?}");
        assert!(!file.exists(), "the new session must not land in the owner-only file");
        assert!(marker.exists(), "the marker is put back over a login keychain that may still hold the app's item");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A removal that reported success and did not take leaves the app's own item standing, and the add refuses it; the marker the write removed is put back, so a later read the store will not answer refuses rather than reading as a first run.
    #[test]
    fn an_occupied_fresh_write_over_the_apps_own_item_puts_the_marker_back() {
        let (store, file) = scratch("fresh-own-item-occupied");
        let keychain = TestKeychain { removal_does_not_take: true, ..TestKeychain::holding("the-approver-key") };
        let marker = claimed(&file);

        let err = store
            .store_fresh_to(&file, &marker, "a-new-key", Custody::Native, &keychain.open(), Some(&keychain.add_own()))
            .expect_err("an item the removal left must fail the fresh write");

        assert!(matches!(err, StoreFreshError::Occupied(_)), "{err:?}");
        assert_eq!(String::from(err.clone()), err.to_string(), "store_fresh returns the same text");
        assert_eq!(keychain.held().as_deref(), Some("the-approver-key"));
        assert_eq!(keychain.added_by(), Some(AddedBy::TheApp));
        assert!(marker.exists(), "the marker must be put back over the app's own item");
        assert!(!file.exists());
        assert_eq!(store.load_from(&file, &marker, Custody::Native, &keychain.open()).unwrap().as_deref(), Some("the-approver-key"));
        let quiet = store.decide(Native::Failed("the keychain is locked".into()), &file, &marker);
        assert!(quiet.is_err(), "with the marker back, a store that will not answer is a refusal, not a first run: {quiet:?}");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// One warning stands for every app store in the process, so it names the variable and says that every app store ignores it rather than naming whichever account happened to load first.
    #[test]
    fn the_ignored_override_warning_names_the_variable_and_every_app_store() {
        let warning = ignored_override_warning("PERMAURA_VAULT_CUSTODY");
        assert!(warning.contains("PERMAURA_VAULT_CUSTODY"), "{warning}");
        assert!(warning.contains("every app credential store"), "{warning}");
    }

    /// An ignored override is reported once per process, not on every load and store.
    #[test]
    fn an_ignored_override_is_reported_once() {
        let reported = AtomicBool::new(false);
        assert!(report_ignored("PERMAURA_VAULT_CUSTODY", &reported));
        assert!(!report_ignored("PERMAURA_VAULT_CUSTODY", &reported));
        assert!(!report_ignored("PERMAURA_VAULT_CUSTODY", &reported));
    }

    /// The default home must keep the exact account name it has always used. Suffixing it would tell
    /// every existing install its key had vanished, which is the mint-over-a-live-vault move this
    /// whole module exists to prevent.
    #[test]
    fn the_default_home_addresses_the_bare_account_name() {
        let (store, file) = scratch("default-home-account");
        // A scratch HOME rather than the real one, read under the same lock as every test that sets it.
        let home = file.parent().expect("scratch dir").join("a-user-home");
        // Pointing the variable AT the default is still the default: the comparison is between
        // resolved paths, not between "set" and "unset".
        with_homes(&home.join(".permaura"), Some(&home), || {
            assert_eq!(store.account_for_home(), store.account, "the default home must not be suffixed");
            assert_eq!(store.legacy_account(), None, "and it has no older name to fall back to");
        });
    }

    /// Any program running as the user can set the app's `PERMAURA_HOME` and `HOME` (`launchctl setenv`, `open --env`). Pointed at a directory it chose, an app store addressed a suffixed account where nothing of the app's stood, found no marker there, and adopted a file planted beside it. A release Keychain build keeps an app store's file, marker and account on the home the user record gives, unsuffixed; nothing here reads or writes that home.
    #[cfg(all(target_os = "macos", feature = "apple-native"))]
    #[test]
    fn a_release_app_store_takes_its_home_from_the_user_record_not_the_environment() {
        let (app, file) = scratch("user-record-home");
        let planted = file.parent().expect("scratch dir").join("planted-home");
        let real = login_keychain::user_record_home().expect("this test's user has a user record").join(".permaura");
        assert!(!real.starts_with(&planted), "precondition: the planted home is not the user's");

        let (path, marker, account, suffix) = with_homes(&planted, Some(&planted), || {
            (app.path_in(false), app.marker_in(false), app.account_in(false), app.home_suffix(false))
        });

        assert_eq!(path.unwrap(), real.join(app.file_name), "a release app store's file must not follow PERMAURA_HOME");
        assert_eq!(marker.unwrap(), real.join(format!("{}.in-os-store", app.file_name)));
        assert_eq!(account, app.account, "the user record's home is the default one, so the account is unsuffixed whatever HOME says");
        assert_eq!(suffix, None, "and there is no pre-scoping name to fall back to");
    }

    /// The gateway's vault KEK takes its home from the environment in every build, and an app store does in a debug build and off the Keychain build, so a relocated home keeps its own file, marker and suffixed account there.
    #[test]
    fn a_server_store_and_a_debug_build_keep_the_environments_home() {
        let (app, file) = scratch("env-home");
        let relocated = file.parent().expect("scratch dir").join("relocated-home");
        let server = CredentialStore { operator_sets_custody: true, ..app };
        let mut cases = vec![("a server store in a release build", &server, false), ("an app store in a debug build", &app, true)];
        if !APP_HOME_IN_USER_RECORD {
            cases.push(("an app store in a release build off the Keychain build", &app, false));
        }
        with_home(&relocated, || {
            for (who, store, home_from_env_build) in cases {
                assert_eq!(store.path_in(home_from_env_build).unwrap(), relocated.join(store.file_name), "{who}");
                assert_eq!(
                    store.marker_in(home_from_env_build).unwrap(),
                    relocated.join(format!("{}.in-os-store", store.file_name)),
                    "{who}"
                );
                assert!(store.account_in(home_from_env_build).starts_with(&format!("{}@", store.account)), "{who}");
            }
        });
    }

    /// Two installs on one machine must not reach for the same entry. Before this, they did: the first
    /// to adopt put its key in the store, the second found it, and both sealed separate vaults under
    /// one key with nothing to say so.
    #[test]
    fn a_relocated_home_gets_an_account_of_its_own() {
        let (store, _file) = scratch("scoped-home-account");
        let a = std::env::temp_dir().join("permaura-scope-a");
        let b = std::env::temp_dir().join("permaura-scope-b");

        let name_a = with_home(&a, || store.account_for_home());
        let name_b = with_home(&b, || store.account_for_home());

        assert_ne!(name_a, store.account, "a relocated home must not use the bare name");
        assert_ne!(name_a, name_b, "two homes must not collide on one entry");
        assert!(name_a.starts_with(&format!("{}@", store.account)), "got {name_a}");
        // Stable across calls, or an install would lose its own key on the next launch.
        assert_eq!(name_a, with_home(&a, || store.account_for_home()));
        // A relocated home with no marker of its own must NOT reach for the old name: doing so would
        // hand it the default install's key, which is the collision this scoping exists to end.
        std::fs::create_dir_all(&a).ok();
        let _ = std::fs::remove_file(a.join(format!("{}.in-os-store", store.file_name)));
        assert_eq!(
            with_home(&a, || store.legacy_account()),
            None,
            "a fresh relocated home has nothing to migrate and must stay isolated"
        );

        // Once it HAS adopted something, the old name is where that something may be.
        CredentialStore::claim_for_store(&a.join(format!("{}.in-os-store", store.file_name))).unwrap();
        assert_eq!(with_home(&a, || store.legacy_account()), Some(store.account.to_string()));
        std::fs::remove_dir_all(&a).ok();
    }





    /// A caller that cannot answer a macOS authorization dialog must not put anything in the Keychain
    /// it will be asked about again after its next update. This test binary is ad-hoc signed, exactly
    /// like the published gateway, so on macOS it exercises the real refusal; elsewhere no store gates
    /// reads on code identity and the flag must change nothing at all.
    #[test]
    fn a_caller_needing_a_stable_identity_gets_the_file_from_an_unsigned_build() {
        if cfg!(all(target_os = "macos", feature = "apple-native")) {
            assert!(!stable_code_identity(), "a cargo test binary is ad-hoc signed, not Developer ID");
            let Custody::Unavailable(why) = Custody::of(true, false) else {
                panic!("an unsigned build must not take Keychain custody for a caller that needs one");
            };
            assert!(why.contains("Developer ID"), "the refusal must name the real cause: {why}");
        } else {
            assert!(stable_code_identity(), "only macOS Keychain ACLs key on code identity");
            assert_eq!(Custody::of(true, false), Custody::of(false, false));
        }
    }

    /// Minting is allowed on exactly one answer, and `resolve_or_create` must not widen it. A store
    /// that refuses for a secret the marker says it holds has to propagate, not fall through to a
    /// fresh key: the fall-through is what re-keys a live vault.
    #[test]
    fn a_refusal_is_never_answered_with_a_fresh_secret() {
        let (store, file) = scratch("no-mint-on-refusal");
        let err = store
            .decide(Native::Failed("locked".into()), &file, &claimed(&file))
            .expect_err("must refuse");
        assert!(err.contains("Refusing to mint a replacement"));
        assert_eq!(CredentialStore::load_file(&file).unwrap(), None, "nothing may have been written");
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A generated secret is opaque bytes, but the encoding still has to be safe to put in a file, an
    /// environment block or a keychain item without escaping.
    #[test]
    fn a_generated_secret_is_high_entropy_ascii_and_unique() {
        let a = generate_secret();
        assert_eq!(a.len(), 43, "32 bytes as unpadded base64");
        assert!(a.is_ascii() && !a.contains('=') && !a.chars().any(char::is_whitespace));
        assert_ne!(a, generate_secret());
    }

    #[test]
    fn the_file_half_round_trips() {
        let (store, file) = scratch("round-trip");
        CredentialStore::store_file(&file, "a-secret").unwrap();
        assert_eq!(store.resolve_from(&file, &never_claimed(&file), Custody::NoStore, &no_store, FileRead::Asked).unwrap(), Source::File("a-secret".into()));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// An app store that names an access group keeps it in the data-protection keychain only in a release build that has that keychain; a debug build, a server's own store and a store naming no group keep the keychain they had.
    #[test]
    fn only_a_release_app_store_naming_a_group_uses_the_data_protection_keychain() {
        const GROUP: &str = "TEAMID.com.permaura.test";
        let (no_group, _file) = scratch("data-protection-choice");
        let app = CredentialStore { keychain_access_group: Some(GROUP), ..no_group };
        let expected = if HAS_DATA_PROTECTION { Some(GROUP) } else { None };
        assert_eq!(app.data_protection_in(false), expected);
        assert_eq!(app.data_protection_in(true), None, "a debug build is not signed into the group");
        assert_eq!(CredentialStore { operator_sets_custody: true, ..app }.data_protection_in(false), None);
        assert_eq!(CredentialStore { keychain_access_group: None, ..app }.data_protection_in(false), None);
    }

    /// A store kept in the data-protection keychain never asks its owner-only file, even through `load`; every other store keeps the load its caller chose.
    #[test]
    fn a_data_protection_store_never_asks_its_owner_only_file() {
        const GROUP: &str = "TEAMID.com.permaura.test";
        let (no_group, _file) = scratch("data-protection-file-read");
        let app = CredentialStore { keychain_access_group: Some(GROUP), ..no_group };
        let release = if HAS_DATA_PROTECTION { FileRead::Skipped } else { FileRead::Asked };
        assert_eq!(app.file_read_for(FileRead::Asked, false), release);
        assert_eq!(app.file_read_for(FileRead::Skipped, false), FileRead::Skipped);
        assert_eq!(app.file_read_for(FileRead::Asked, true), FileRead::Asked, "a debug build keeps the login keychain and its file");
        assert_eq!(CredentialStore { keychain_access_group: None, ..app }.file_read_for(FileRead::Asked, false), FileRead::Asked);
        assert_eq!(CredentialStore { operator_sets_custody: true, ..app }.file_read_for(FileRead::Asked, false), FileRead::Asked);
    }

    /// The data-protection keychain's marker has a name of its own, so the claim a login-keychain item left behind never says the data-protection keychain lost something; the login keychain's marker keeps its name.
    #[test]
    fn the_data_protection_keychain_has_a_marker_of_its_own() {
        let (no_group, file) = scratch("data-protection-marker");
        let app = CredentialStore { keychain_access_group: Some("TEAMID.com.permaura.test"), ..no_group };
        with_home(file.parent().unwrap(), || {
            let login = CredentialStore { keychain_access_group: None, ..app }.marker_for(true, false).unwrap();
            assert!(login.to_string_lossy().ends_with(".in-os-store"), "{}", login.display());
            let release = app.marker_for(true, false).unwrap();
            let debug = app.marker_for(true, true).unwrap();
            assert_eq!(debug, login, "a debug build keeps the login keychain and its marker");
            if HAS_DATA_PROTECTION {
                assert!(release.to_string_lossy().ends_with(".in-data-protection-keychain"), "{}", release.display());
            } else {
                assert_eq!(release, login);
            }
        });
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// The first load after the upgrade: the login keychain's claim stands and its item may be anything, and the data-protection keychain holds nothing, so the load is empty rather than a refusal and the pairing mints a key of this Mac's own.
    #[test]
    fn a_first_data_protection_load_beside_a_login_keychain_claim_finds_nothing_stored() {
        let (store, file) = scratch("data-protection-first-load");
        let login_claim = claimed(&file);
        let marker = file.with_extension("in-data-protection-keychain");
        let empty = TestKeychain::default();

        let loaded = store.load_in(&file, &marker, Custody::Native, &empty.open(), FileRead::Skipped);

        assert_eq!(loaded, Ok(None));
        assert!(login_claim.exists() && !marker.exists());
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A routine write the data-protection keychain refuses fails and writes no owner-only file, which nothing reads for a store kept there; the marker is left as it was.
    #[test]
    fn a_routine_write_the_data_protection_keychain_refuses_writes_no_file() {
        let (store, file) = scratch("data-protection-routine");
        let keychain = TestKeychain { data_protection_refuses: true, ..TestKeychain::holding("pins-1") };
        let marker = file.with_extension("in-data-protection-keychain");
        CredentialStore::claim_for_store(&marker).unwrap();

        let why = store.store_to(&file, &marker, "pins-2", Custody::Native, &keychain.open()).expect_err("a refused write must fail");

        assert!(why.message().contains("data-protection keychain refused it"), "{why}");
        assert!(!file.exists(), "a refused write must not land in the owner-only file");
        assert!(marker.exists());
        assert_eq!(keychain.held().as_deref(), Some("pins-1"));
        std::fs::remove_dir_all(file.parent().unwrap()).ok();
    }

    /// A release app store naming a group opens a data-protection keychain item and never a login keychain one; opening touches no keychain.
    #[cfg(all(target_os = "macos", feature = "apple-data-protection"))]
    #[test]
    fn a_release_app_store_naming_a_group_opens_a_data_protection_item() {
        let (no_group, _file) = scratch("data-protection-entry");
        let app = CredentialStore { keychain_access_group: Some("TEAMID.com.permaura.test"), ..no_group };
        let entry = app.entry_in("data-protection-entry", false).expect("an entry opens without a keychain");
        assert!(entry.get_credential().downcast_ref::<data_protection::DataProtectionItem>().is_some());
        assert!(entry.get_credential().downcast_ref::<login_keychain::LoginKeychainItem>().is_none());
        let debug = app.entry_in("data-protection-entry", true).expect("an entry opens without a keychain");
        assert!(debug.get_credential().downcast_ref::<login_keychain::LoginKeychainItem>().is_some());
    }
}

