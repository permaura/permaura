//! Private file creation, children that die with the gateway ([`child`]), and the exclusive lock a store is held by. Platform FFI stays outside the safe security core.
//! These protect against other OS identities, not hostile processes with the owner's identity.

use std::{
    fs::File,
    io::{self},
    path::Path,
};

#[cfg(feature = "lock")]
mod lock;
#[cfg(feature = "lock")]
pub use lock::{open_lock_file, try_lock_exclusive};

/// Create a new file with no group/world or inherited access, before its first byte.
/// Existing paths, including symlinks, are refused. The parent directory must not be writable by
/// an untrusted identity. Owner-private access does not isolate processes running as that owner.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        windows::create(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private files unsupported on this platform",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Security::Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        Security::{GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER},
        Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, READ_CONTROL},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    pub(super) fn create(path: &Path) -> io::Result<File> {
        // SAFETY: every output buffer is sized by the corresponding Win32 API; handles and
        // LocalAlloc results are released on every path. The returned file owns its handle.
        unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
            // usize storage supplies TOKEN_USER's pointer alignment.
            let mut buffer =
                vec![0usize; (len as usize + size_of::<usize>() - 1) / size_of::<usize>()];
            let ok =
                GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len);
            let error = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(error);
            }
            let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
            let mut sid = ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut n = 0;
            while *sid.add(n) != 0 {
                n += 1;
            }
            let owner = String::from_utf16_lossy(std::slice::from_raw_parts(sid, n));
            LocalFree(sid.cast());
            // Protected DACL, exactly the current user and SYSTEM. Parent ACEs are not inherited.
            let sddl: Vec<u16> = format!("O:{owner}D:P(A;;FA;;;{owner})(A;;FA;;;SY)")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attrs = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let name: Vec<u16> = path.as_os_str().encode_wide().collect();
            if name.contains(&0) {
                LocalFree(descriptor);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NUL in file path",
                ));
            }
            let name: Vec<u16> = name.into_iter().chain(Some(0)).collect();
            let handle = CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE | READ_CONTROL,
                0,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            let error = io::Error::last_os_error();
            LocalFree(descriptor);
            if handle == INVALID_HANDLE_VALUE {
                return Err(error);
            }
            Ok(File::from_raw_handle(handle))
        }
    }
}

#[cfg(feature = "child")]
pub mod child;

#[cfg(test)]
mod tests;
