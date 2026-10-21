use super::*;

#[test]
fn creation_refuses_existing_files_without_truncating() {
    let path = std::env::temp_dir().join(format!("permaura-create-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut file = create_private_file(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
    use std::io::Write;
    file.write_all(b"original").unwrap();
    drop(file);
    assert_eq!(
        create_private_file(&path).unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
    std::fs::remove_file(path).unwrap();
}

#[cfg(windows)]
mod windows_tests {
    use super::*;
    use std::{os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{LocalFree, ERROR_SUCCESS},
        Security::Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT},
        Security::{
            GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACL,
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
    };

    unsafe fn sid_string(sid: *mut std::ffi::c_void) -> String {
        let mut text = ptr::null_mut();
        assert_ne!(ConvertSidToStringSidW(sid, &mut text), 0);
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text.cast());
        result
    }

    // Inspect the actual open file handle, before writing or closing it. Checking the eventual
    // destination after a post-write chmod/DACL repair would miss precisely this vulnerability.
    fn acl(file: &File) -> (bool, String, Vec<(String, u32, u8, u8)>) {
        unsafe {
            let mut descriptor = ptr::null_mut();
            let mut owner = ptr::null_mut();
            let mut dacl: *mut ACL = ptr::null_mut();
            assert_eq!(
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    &mut owner,
                    ptr::null_mut(),
                    &mut dacl,
                    ptr::null_mut(),
                    &mut descriptor
                ),
                ERROR_SUCCESS
            );
            assert!(!dacl.is_null());
            let mut control = 0;
            let mut revision = 0;
            assert_ne!(
                GetSecurityDescriptorControl(descriptor, &mut control, &mut revision),
                0
            );
            let owner = sid_string(owner);
            let mut entries = Vec::new();
            for i in 0..(*dacl).AceCount as u32 {
                let mut raw = ptr::null_mut();
                assert_ne!(GetAce(dacl, i, &mut raw), 0);
                let ace = &*(raw as *const ACCESS_ALLOWED_ACE);
                assert_eq!(ace.Header.AceType, 0, "fixture contains only allow ACEs");
                entries.push((
                    sid_string(ptr::addr_of!(ace.SidStart) as *mut _),
                    ace.Mask,
                    ace.Header.AceFlags,
                    ace.Header.AceType,
                ));
            }
            LocalFree(descriptor);
            (control & SE_DACL_PROTECTED != 0, owner, entries)
        }
    }

    #[test]
    fn permissive_parent_cannot_expose_file_before_first_write() {
        let dir =
            std::env::temp_dir().join(format!("permaura-creation-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let output = std::process::Command::new("icacls.exe")
            .arg(&dir)
            .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "could not make permissive fixture: {output:?}"
        );
        let inherited = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("inherited-control"))
            .unwrap();
        assert!(
            acl(&inherited).2.iter().any(|a| a.0 == "S-1-1-0"),
            "control must demonstrate the inherited Everyone ACE the regression would expose"
        );
        drop(inherited);
        let mut file = create_private_file(&dir.join(".kek.tmp-fixture")).unwrap();
        let (protected, owner, entries) = acl(&file);
        assert!(protected);
        assert_eq!(entries.len(), 2);
        for (sid, mask, flags, kind) in &entries {
            assert!(sid == &owner || sid == "S-1-5-18");
            assert_eq!(*mask, FILE_ALL_ACCESS);
            assert_eq!(*flags, 0);
            assert_eq!(*kind, 0);
        }
        assert!(entries.iter().any(|a| a.0 == owner));
        assert!(entries.iter().any(|a| a.0 == "S-1-5-18"));
        use std::io::Write;
        file.write_all(b"synthetic secret").unwrap();
        drop(file);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn nul_in_path_is_refused() {
        assert_eq!(
            create_private_file(Path::new("invalid\0path"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

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

/// The platform crate's `TOKEN_USER` read stays on `usize` storage, the alignment the credential store's copy now matches.
#[test]
fn a_token_user_is_read_only_from_pointer_aligned_storage() {
    let (found, offending) = token_user_buffers(include_str!("lib.rs"));
    assert!(found > 0, "the scan finds the read it guards");
    assert_eq!(offending, Vec::<String>::new());
}
