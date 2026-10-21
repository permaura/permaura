//! An app store's Keychain items, kept in the user's login keychain and addressed by its path.
//!
//! keyring reaches every item through `SecKeychainCopyDomainDefault(User)`, the user-domain default keychain, and that default is a per-user preference any program running as the user can repoint (`SecKeychainSetDomainDefault`, `security default-keychain -d user -s`) at a keychain whose password it set. The app's next sign-in would then land in a keychain that program decrypts offline, whatever the item's access list says. So an app store names its keychain itself, on every read, removal, write and add: `Library/Keychains/login.keychain-db` under the home the user record gives.
//!
//! A login keychain that cannot be found or opened is [`NoLoginKeychain`], which every caller meets as a refusal: nothing here falls back to the default keychain.

use std::path::{Path, PathBuf};

use keyring::credential::CredentialApi;
use security_framework::base::Error as SecError;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::passwords::find_generic_password;

use crate::{AddRefused, NoLoginKeychain};

/// The login keychain's file, under the user's home.
const LOGIN_KEYCHAIN: &str = "Library/Keychains/login.keychain-db";

/// One generic password in the user's login keychain.
#[derive(Debug, Clone)]
pub(crate) struct LoginKeychainItem {
    service: String,
    account: String,
}

impl LoginKeychainItem {
    /// Refuses an empty service or account, which the Keychain's search reads as a wildcard, as keyring does.
    pub(crate) fn new(service: &str, account: &str) -> Result<Self, String> {
        if service.is_empty() || account.is_empty() {
            return Err("a Keychain item needs both a service and an account".into());
        }
        Ok(Self { service: service.into(), account: account.into() })
    }

    /// The Keychain's add, which refuses an item already standing under the service and account; with no initial access the item gets the default access list, naming this app.
    pub(crate) fn add(&self, secret: &str) -> Result<(), AddRefused> {
        login_keychain()
            .map_err(AddRefused::NoLoginKeychain)?
            .add_generic_password(&self.service, &self.account, secret.as_bytes())
            .map_err(crate::keychain_add_refusal)
    }
}

impl CredentialApi for LoginKeychainItem {
    /// keyring's write, on the login keychain: an item it finds is modified in place and keeps its access list, and one is added when none stands.
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        login_keychain()?.set_generic_password(&self.service, &self.account, secret).map_err(decode)
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        let (secret, _) =
            find_generic_password(Some(&[login_keychain()?]), &self.service, &self.account).map_err(decode)?;
        Ok(secret.to_owned())
    }

    /// keyring's removal, on the login keychain. The Keychain's delete reports nothing, so a removal that did not take reaches a fresh write's add, which refuses it.
    fn delete_credential(&self) -> keyring::Result<()> {
        let (_, item) =
            find_generic_password(Some(&[login_keychain()?]), &self.service, &self.account).map_err(decode)?;
        item.delete();
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// The user's login keychain, opened by its path.
fn login_keychain() -> Result<SecKeychain, NoLoginKeychain> {
    if cfg!(test) {
        panic!("a unit test reached the user's real login keychain");
    }
    let path = login_keychain_path(&user_record_home().map_err(NoLoginKeychain)?)?;
    SecKeychain::open(&path).map_err(|e| NoLoginKeychain(format!("{} could not be opened: {e}", path.display())))
}

/// This user's home as the user record gives it, never `HOME`, which any program running as the user can set in the app's environment.
pub(crate) fn user_record_home() -> Result<PathBuf, String> {
    use nix::unistd::{Uid, User};
    match User::from_uid(Uid::current()) {
        Ok(Some(user)) => Ok(user.dir),
        Ok(None) => Err("this process's user has no user record to find a home in".into()),
        Err(e) => Err(format!("the user record could not be read: {e}")),
    }
}

/// The login keychain's file under `home`, which must already be there: the Keychain opens a path that names nothing, and a search of it may then answer "no such item" where the truth is "no such keychain".
fn login_keychain_path(home: &Path) -> Result<PathBuf, NoLoginKeychain> {
    let path = home.join(LOGIN_KEYCHAIN);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => Ok(path),
        Ok(_) => Err(NoLoginKeychain(format!("{} is not a keychain file", path.display()))),
        Err(e) => Err(NoLoginKeychain(format!("{} could not be read: {e}", path.display()))),
    }
}

/// Keychain statuses, from SecBase.h.
const NOT_AVAILABLE: i32 = -25291;
const READ_ONLY: i32 = -25292;
const NO_SUCH_KEYCHAIN: i32 = -25294;
const INVALID_KEYCHAIN: i32 = -25295;
const ITEM_NOT_FOUND: i32 = -25300;

/// Whether a Keychain status says the keychain itself is missing or is not one, which for the login keychain is a refusal and never an empty store.
pub(crate) fn names_no_keychain(e: &SecError) -> bool {
    matches!(e.code(), NO_SUCH_KEYCHAIN | INVALID_KEYCHAIN)
}

/// keyring's reading of a Keychain status, except that a missing login keychain is [`NoLoginKeychain`].
fn decode(e: SecError) -> keyring::Error {
    match e.code() {
        ITEM_NOT_FOUND => keyring::Error::NoEntry,
        _ if names_no_keychain(&e) => NoLoginKeychain(e.to_string()).into(),
        NOT_AVAILABLE | READ_ONLY => keyring::Error::NoStorageAccess(Box::new(e)),
        _ => keyring::Error::PlatformFailure(Box::new(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// None of these opens a keychain: the path is resolved and checked, and that is all.
    #[test]
    fn the_login_keychain_is_the_file_under_the_home_and_must_be_there() {
        let home = std::env::temp_dir().join(format!("permaura-login-keychain-{}", std::process::id()));
        let keychains = home.join("Library/Keychains");
        std::fs::create_dir_all(&keychains).unwrap();
        let path = keychains.join("login.keychain-db");

        let missing = login_keychain_path(&home).expect_err("a login keychain that is not there must not resolve");
        assert!(missing.0.contains("login.keychain-db"), "the refusal must name the file: {missing}");

        std::fs::create_dir_all(&path).unwrap();
        assert!(login_keychain_path(&home).is_err(), "a directory is not a keychain file");
        std::fs::remove_dir(&path).unwrap();

        std::fs::write(&path, b"").unwrap();
        assert_eq!(login_keychain_path(&home).unwrap(), path);
        std::fs::remove_dir_all(&home).ok();
    }

    /// The home comes from the user record, so it is an absolute path whatever `HOME` holds.
    #[test]
    fn the_home_comes_from_the_user_record() {
        let home = user_record_home().expect("this test's user has a user record");
        assert!(home.is_absolute(), "{}", home.display());
    }

    /// A keychain that is missing or is not one refuses, and a missing item is the only empty answer.
    #[test]
    fn a_missing_keychain_is_a_refusal_and_only_a_missing_item_is_empty() {
        for code in [-25294, -25295] {
            let e = decode(SecError::from_code(code));
            assert!(crate::missing_login_keychain(&e).is_some(), "{code}: {e}");
        }
        assert!(matches!(decode(SecError::from_code(-25300)), keyring::Error::NoEntry));
        assert!(matches!(decode(SecError::from_code(-25308)), keyring::Error::PlatformFailure(_)));
        assert!(LoginKeychainItem::new("", "account").is_err() && LoginKeychainItem::new("service", "").is_err());
    }
}
