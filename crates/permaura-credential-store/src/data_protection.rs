//! An app store's Keychain items in the data-protection keychain, under the app's own keychain access group.
//!
//! In the login keychain any program running as the user can add an item under the app's service and account before the app first writes one, and the app then reads that item as its own: a planted approver key was sent at the owner's first pairing. The data-protection keychain keeps items by access group, and only code signed with that group in its `keychain-access-groups` entitlement can add, read, change or remove an item in it. On macOS that entitlement is restricted: the system launches code claiming it only under a provisioning profile Apple issued for the app's team and identifier, so no other program running as the user can claim the group.
//!
//! A build signed without the group gets errSecMissingEntitlement from every call, which every caller meets as a refusal: nothing here falls back to the login keychain or the owner-only file. An item the login keychain holds under the same service and account is never read from here, so a key planted there, or written there by an earlier build, is not this Mac's.

use keyring::credential::CredentialApi;
use security_framework_3::access_control::{ProtectionMode, SecAccessControl};
use security_framework_3::base::Error as SecError;
use security_framework_3::passwords::{
    delete_generic_password_options, generic_password, set_generic_password_options, PasswordOptions,
};

use crate::{AddRefused, DataProtectionRefused};

/// Keychain statuses, from SecBase.h.
const ITEM_NOT_FOUND: i32 = -25300;
const MISSING_ENTITLEMENT: i32 = -34018;

/// One generic password in the data-protection keychain, under one access group.
#[derive(Debug, Clone)]
pub(crate) struct DataProtectionItem {
    service: String,
    account: String,
    access_group: &'static str,
}

impl DataProtectionItem {
    /// Refuses an empty service, account or group, which the Keychain's search reads as a wildcard.
    pub(crate) fn new(service: &str, account: &str, access_group: &'static str) -> Result<Self, String> {
        if service.is_empty() || account.is_empty() || access_group.is_empty() {
            return Err("a data-protection keychain item needs a service, an account and an access group".into());
        }
        Ok(Self { service: service.into(), account: account.into(), access_group })
    }

    /// A fresh write's add, refused while an item stands under the service and account. Only code signed into this access group can have added one, so a standing item is this app's own whose removal did not take, never another program's.
    ///
    /// The check and the add are two calls, and the add writes over an item that appears between them rather than refusing it. Only another copy of this app can add one there, and single-instance keeps a second copy from running.
    pub(crate) fn add(&self, secret: &str) -> Result<(), AddRefused> {
        match generic_password(self.options()) {
            Ok(_) => return Err(AddRefused::Occupied),
            Err(e) if e.code() == ITEM_NOT_FOUND => {}
            Err(e) => return Err(AddRefused::Failed(describe(&e))),
        }
        self.add_new(secret.as_bytes()).map_err(|e| AddRefused::Failed(describe(&e)))
    }

    /// Adds the item, readable from the first unlock after a restart, so a poll behind a locked screen still reads it, and never carried to another Mac by a backup or a migration.
    fn add_new(&self, secret: &[u8]) -> Result<(), SecError> {
        let mut options = self.options();
        options.set_access_control(SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )?);
        set_generic_password_options(secret, options)
    }

    /// The service, account and group, in the data-protection keychain.
    fn options(&self) -> PasswordOptions {
        if cfg!(test) {
            panic!("a unit test reached the user's real data-protection keychain");
        }
        let mut options = PasswordOptions::new_generic_password(&self.service, &self.account);
        options.use_protected_keychain();
        options.set_access_group(self.access_group);
        options
    }
}

impl CredentialApi for DataProtectionItem {
    /// keyring's write: an item that stands is changed in place and keeps its attributes, and one is added when none does. Every failure is a refusal, never "no such item", so a write that loses a race with a removal is not taken for a store with nothing in it.
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        let written = match generic_password(self.options()) {
            Ok(_) => set_generic_password_options(secret, self.options()),
            Err(e) if e.code() == ITEM_NOT_FOUND => self.add_new(secret),
            Err(e) => Err(e),
        };
        written.map_err(|e| DataProtectionRefused(describe(&e)).into())
    }

    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        generic_password(self.options()).map_err(decode)
    }

    fn delete_credential(&self) -> keyring::Result<()> {
        delete_generic_password_options(self.options()).map_err(decode)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// keyring's reading of a Keychain status: a missing item is the only empty answer, and anything else is [`DataProtectionRefused`].
fn decode(e: SecError) -> keyring::Error {
    match e.code() {
        ITEM_NOT_FOUND => keyring::Error::NoEntry,
        _ => DataProtectionRefused(describe(&e)).into(),
    }
}

/// A status as a person reads it, naming the missing entitlement, which is what a build signed without the profile gets.
fn describe(e: &SecError) -> String {
    match e.code() {
        MISSING_ENTITLEMENT => format!("this build is not signed with the keychain access group it names ({e})"),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing item is the only empty answer; a build without the entitlement, a locked keychain and anything else refuse. No check opens the Keychain.
    #[test]
    fn a_missing_item_is_the_only_empty_answer() {
        assert!(matches!(decode(SecError::from_code(ITEM_NOT_FOUND)), keyring::Error::NoEntry));
        for code in [MISSING_ENTITLEMENT, -25308, -25291] {
            let e = decode(SecError::from_code(code));
            let refused = crate::data_protection_refusal(&e).unwrap_or_else(|| panic!("{code} must refuse: {e}"));
            if code == MISSING_ENTITLEMENT {
                assert!(refused.0.contains("keychain access group"), "{refused}");
            }
        }
        assert!(DataProtectionItem::new("", "account", "TEAM.group").is_err());
        assert!(DataProtectionItem::new("service", "", "TEAM.group").is_err());
        assert!(DataProtectionItem::new("service", "account", "").is_err());
    }
}
