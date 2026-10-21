//! An owner-only ACL for a file holding secret material, on the one platform where mode bits are not
//! the answer.
//!
//! Unix is handled where the file is created: `permaura_core::write_secret_file` and
//! `replace_secret_file` open at `0600`, so the secret is private from its first byte and there is no
//! window left to close. Windows creation is handled by `permaura-platform`, which passes a
//! protected security descriptor to `CreateFileW`. This module can also narrow an existing file;
//! it must never be used as a substitute for a private creation descriptor.
//!
//! Two ACEs and no more: the account this process is running as, and `SYSTEM`. `SYSTEM` is there
//! because backup, indexing and repair run as it, and a file it cannot touch produces failures that
//! read as disk corruption. Administrators is deliberately absent: an admin can take ownership anyway,
//! so listing it buys nothing and widens the set of accounts that can read the file without having to.
//!
//! This module is the reason this crate says `deny(unsafe_code)` rather
//! than `forbid`. `permaura-core` cannot host it: core forbids unsafe outright and links no platform
//! crate.

#![allow(unsafe_code)]

use std::io;
use std::path::Path;

/// Narrow `path` to a protected, owner-only ACL: exactly two allow ACEs, the account this process runs
/// as and `SYSTEM`, with inheritance from the parent directory switched off.
///
/// Call it immediately after creating a file that holds secret material, on every platform. Off
/// Windows it is a no-op returning `Ok`, because the file was created `0600` and there is nothing left
/// to do.
///
/// The error is the caller's to handle rather than something to log and swallow. A file whose ACL
/// could not be written is a secret sitting under whatever it inherited, and only the caller knows
/// whether that is worth failing the write over.
#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let mut owner = current_owner_sid()?;
    let mut system = local_system_sid()?;

    let ace = |sid: *mut u8, kind: i32| EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: kind,
            ptstrName: sid.cast(),
        },
    };
    let entries = [
        ace(owner.as_mut_ptr(), TRUSTEE_IS_USER),
        ace(system.as_mut_ptr(), TRUSTEE_IS_WELL_KNOWN_GROUP),
    ];

    // SAFETY: `entries` borrows `owner` and `system`, which outlive both calls; the ACL the first call
    // allocates is freed exactly once on every path out; nothing here is shared across threads.
    unsafe {
        // A NULL "existing ACL" is what makes this a replacement rather than an addition: the result
        // holds these two ACEs and nothing else.
        let mut acl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(2, entries.as_ptr(), std::ptr::null_mut(), &mut acl);
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        // PROTECTED is the half that matters. Without it these ACEs are merged with whatever the parent
        // directory hands down, and an inherited "Users: read" survives the whole exercise.
        let rc = SetNamedSecurityInfoW(
            wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl,
            std::ptr::null_mut(),
        );
        LocalFree(acl.cast());
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
    }
    Ok(())
}

/// No-op: the file was created `0600`, which is the whole of the guarantee on this platform.
#[cfg(not(windows))]
pub fn restrict_to_owner(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// The SID of the account this process is running as, copied out of the process token so it owns its
/// own storage rather than pointing into a buffer the caller has to keep alive.
#[cfg(windows)]
fn current_owner_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: the token handle is closed on both paths out, `token_info` is `usize` storage, which
    // supplies the pointer alignment `TOKEN_USER` needs, and the SID is copied before it is dropped.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        // The documented two-call shape: the first asks how big the answer is and is expected to fail.
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        let mut token_info = vec![0usize; (needed.max(1) as usize).div_ceil(std::mem::size_of::<usize>())];
        let read =
            GetTokenInformation(token, TokenUser, token_info.as_mut_ptr().cast(), needed, &mut needed);
        CloseHandle(token);
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid = (*(token_info.as_ptr() as *const TOKEN_USER)).User.Sid;
        let len = GetLengthSid(sid) as usize;
        Ok(std::slice::from_raw_parts(sid as *const u8, len).to_vec())
    }
}

/// The well-known `SYSTEM` SID, built rather than looked up by name, so a localised Windows and a
/// machine with no reachable domain controller both produce the same answer.
#[cfg(windows)]
fn local_system_sid() -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, WinLocalSystemSid, SECURITY_MAX_SID_SIZE};

    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = sid.len() as u32;
    // SAFETY: the buffer is `SECURITY_MAX_SID_SIZE`, the documented upper bound for any SID.
    let made = unsafe {
        CreateWellKnownSid(WinLocalSystemSid, std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut len)
    };
    if made == 0 {
        return Err(io::Error::last_os_error());
    }
    sid.truncate(len as usize);
    Ok(sid)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl, AclSizeInformation, ACCESS_ALLOWED_ACE,
        ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    };

    /// `ACCESS_ALLOWED_ACE_TYPE` from winnt.h. windows-sys does not export it, and the value is fixed
    /// by the on-disk ACE format, so it cannot drift.
    const ACCESS_ALLOWED: u8 = 0;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("permaura-dacl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// One ACE as this test cares about it: who it names, and whether it inherits.
    struct Ace {
        sid: Vec<u8>,
        allowed: bool,
        flags: u8,
    }

    /// Read back the DACL Windows actually stored, so the assertions are about the file on disk rather
    /// than about the arguments that were passed in.
    fn dacl_of(path: &std::path::Path) -> (bool, Vec<Ace>) {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let rc = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(rc, ERROR_SUCCESS, "reading the DACL back failed");

            let mut control: u16 = 0;
            let mut revision: u32 = 0;
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0,
                "reading the descriptor control failed"
            );
            let protected = control & SE_DACL_PROTECTED != 0;

            let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
            assert_ne!(
                GetAclInformation(
                    acl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ),
                0,
                "reading the ACE count failed"
            );

            let mut aces = Vec::new();
            for i in 0..info.AceCount {
                let mut raw: *mut std::ffi::c_void = std::ptr::null_mut();
                assert_ne!(GetAce(acl, i, &mut raw), 0, "reading ACE {i} failed");
                let ace = raw as *const ACCESS_ALLOWED_ACE;
                let sid_ptr = std::ptr::addr_of!((*ace).SidStart) as *const u8;
                let len = windows_sys::Win32::Security::GetLengthSid(sid_ptr as *mut _) as usize;
                aces.push(Ace {
                    sid: std::slice::from_raw_parts(sid_ptr, len).to_vec(),
                    allowed: (*ace).Header.AceType == ACCESS_ALLOWED,
                    flags: (*ace).Header.AceFlags,
                });
            }
            LocalFree(sd.cast());
            (protected, aces)
        }
    }

    fn same_sid(a: &[u8], b: &[u8]) -> bool {
        // SAFETY: both slices came from `GetLengthSid`-sized reads of real SIDs.
        unsafe { EqualSid(a.as_ptr() as *mut _, b.as_ptr() as *mut _) != 0 }
    }

    /// The property: after `restrict_to_owner` the file's DACL is protected, so nothing is inherited
    /// from the directory it lives in, and it names exactly the owner and SYSTEM.
    #[test]
    fn a_secret_file_gets_a_protected_dacl_with_exactly_two_aces() {
        let path = scratch("kek");
        std::fs::write(&path, b"a-real-looking-kek").unwrap();

        restrict_to_owner(&path).expect("writing the DACL must succeed");

        let (protected, aces) = dacl_of(&path);
        assert!(protected, "the DACL must be protected, or the parent's ACEs are still inherited");
        assert_eq!(aces.len(), 2, "exactly the owner and SYSTEM, got {}", aces.len());
        assert!(aces.iter().all(|a| a.allowed), "every ACE must be an allow ACE");
        assert!(aces.iter().all(|a| a.flags == 0), "no ACE may carry an inheritance flag");

        let owner = current_owner_sid().unwrap();
        let system = local_system_sid().unwrap();
        assert!(aces.iter().any(|a| same_sid(&a.sid, &owner)), "the owner must be one of them");
        assert!(aces.iter().any(|a| same_sid(&a.sid, &system)), "and SYSTEM must be the other");

        let _ = std::fs::remove_file(&path);
    }

    /// Applying it twice must converge rather than accumulate. A gateway calls this on every publish
    /// of the operator token, so an ACL that grew an ACE per write would be a slow leak.
    #[test]
    fn applying_it_twice_leaves_the_same_two_aces() {
        let path = scratch("kek-twice");
        std::fs::write(&path, b"v1").unwrap();
        restrict_to_owner(&path).unwrap();
        restrict_to_owner(&path).unwrap();

        let (protected, aces) = dacl_of(&path);
        assert!(protected);
        assert_eq!(aces.len(), 2, "the ACL must not accumulate, got {}", aces.len());

        let _ = std::fs::remove_file(&path);
    }

    /// A path that names nothing must be an error the caller can see, not a silent success. The whole
    /// point of returning `io::Result` is that a secret with no ACL is not quietly accepted.
    #[test]
    fn a_missing_file_is_an_error() {
        let path = scratch("definitely-absent");
        let _ = std::fs::remove_file(&path);
        assert!(restrict_to_owner(&path).is_err());
    }
}

#[cfg(test)]
mod alignment_tests {
    /// The buffers `source` reads a `TOKEN_USER` from, and those of them not declared as `usize` storage: `TOKEN_USER` holds a pointer, and a `Vec<u8>` is only guaranteed alignment 1, so reading one through it is undefined behavior under an allocator that hands back a less-aligned block.
    fn token_user_buffers(source: &str) -> (usize, Vec<String>) {
        let casts = [concat!("as *const ", "TOKEN_USER"), concat!("cast::<", "TOKEN_USER>")];
        let (mut found, mut offending) = (0, Vec::new());
        for line in source.lines().filter(|l| casts.iter().any(|c| l.contains(c))) {
            found += 1;
            let Some(at) = line.find(".as_ptr()") else {
                offending.push(line.trim().to_string());
                continue;
            };
            let name: String = line[..at].chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<Vec<_>>().into_iter().rev().collect();
            let usize_backed = source
                .split(&format!("let mut {name}"))
                .skip(1)
                .any(|rest| rest.trim_start().strip_prefix('=').is_some_and(|value| value.trim_start().starts_with("vec![0usize")));
            if !usize_backed {
                offending.push(name);
            }
        }
        (found, offending)
    }

    /// The class this file had one instance of: the platform crate already reads its `TOKEN_USER` from `usize` storage, and this one now does too.
    #[test]
    fn a_token_user_is_read_only_from_pointer_aligned_storage() {
        let source = include_str!("owner_only.rs").split("mod alignment_tests").next().unwrap();
        let (found, offending) = token_user_buffers(source);
        assert!(found > 0, "the scan finds the read it guards");
        assert_eq!(offending, Vec::<String>::new());
    }
}
