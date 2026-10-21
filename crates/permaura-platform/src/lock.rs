//! An exclusive, advisory lock on an open file, for the one-writer rule on a store.

use std::{fs::File, io, path::Path};

/// Take an exclusive lock on `file` without waiting. `Ok(true)` when this handle now holds it,
/// `Ok(false)` when another handle does.
///
/// The lock belongs to the open handle, not to the process, so a second handle in the same process
/// is refused as well. It lasts until the handle is closed, and the OS releases it when the process
/// ends however it ends, so a crash or a kill never leaves it held. Advisory: it binds only code
/// that asks for it.
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        unix::try_lock(file)
    }
    #[cfg(windows)]
    {
        windows::try_lock(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file locks unsupported on this platform",
        ))
    }
}

/// Open the lock file at `path` read and write, creating it owner-only when `create` asks and it is
/// not there, without following a symbolic link at the path itself, and refusing anything there that is not a
/// regular file before changing it. Returns the file and whether this call created it.
///
/// A link planted at the path, under a store directory another identity can write, would otherwise
/// have its target truncated and re-permissioned by the holder that writes its pid. On Unix a file this
/// call creates while running as root is given to the owner of its directory, so a root opener never
/// leaves a lock the service account cannot open.
pub fn open_lock_file(path: &Path, create: bool) -> io::Result<(File, bool)> {
    #[cfg(unix)]
    {
        unix::open(path, create)
    }
    #[cfg(windows)]
    {
        windows::open(path, create)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, create);
        Err(io::Error::new(io::ErrorKind::Unsupported, "file locks unsupported on this platform"))
    }
}

fn not_a_regular_file(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a regular file (a link or something else is in its place)", path.display()),
    )
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    pub(super) fn open(path: &Path, create: bool) -> io::Result<(File, bool)> {
        let options = |create_new: bool| {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).custom_flags(libc::O_NOFOLLOW);
            if create_new {
                options.create_new(true).mode(0o600);
            }
            options
        };
        let (file, created) = match create {
            true => match options(true).open(path) {
                Ok(file) => (file, true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (options(false).open(path)?, false),
                Err(e) => return Err(e),
            },
            false => (options(false).open(path)?, false),
        };
        if !file.metadata()?.file_type().is_file() {
            return Err(not_a_regular_file(path));
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        // SAFETY: geteuid has no preconditions.
        if created && unsafe { libc::geteuid() } == 0 {
            if let Some(dir) = path.parent().and_then(|d| std::fs::metadata(if d.as_os_str().is_empty() { Path::new(".") } else { d }).ok()) {
                // SAFETY: fchown only reads the descriptor, which `file` keeps open for the call.
                if unsafe { libc::fchown(file.as_raw_fd(), dir.uid(), dir.gid()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok((file, created))
    }

    pub(super) fn try_lock(file: &File) -> io::Result<bool> {
        loop {
            // SAFETY: flock only reads the descriptor, which `file` keeps open for the call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => return Ok(false),
                _ => return Err(error),
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;

    /// Open a reparse point (a symbolic link or junction) as itself rather than what it names.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    pub(super) fn open(path: &Path, create: bool) -> io::Result<(File, bool)> {
        let options = |create_new: bool| {
            let mut options = std::fs::OpenOptions::new();
            options.read(true).write(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            if create_new {
                options.create_new(true);
            }
            options
        };
        let (file, created) = match create {
            true => match options(true).open(path) {
                Ok(file) => (file, true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (options(false).open(path)?, false),
                Err(e) => return Err(e),
            },
            false => (options(false).open(path)?, false),
        };
        let metadata = file.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.file_type().is_file() {
            return Err(not_a_regular_file(path));
        }
        Ok((file, created))
    }
    use windows_sys::Win32::{
        Foundation::ERROR_LOCK_VIOLATION,
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };

    pub(super) fn try_lock(file: &File) -> io::Result<bool> {
        // One byte far past any content: a Windows lock is mandatory for the bytes it covers, and the
        // file's own bytes (the holder's pid) must stay readable to whoever is refused.
        // SAFETY: an all-zero OVERLAPPED is its documented initial state.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.Anonymous.Anonymous.OffsetHigh = u32::MAX;
        // SAFETY: the handle is `file`'s, open for the call; `overlapped` outlives it, and the lock is
        // taken synchronously because the handle was not opened for overlapped I/O.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            return Ok(false);
        }
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_handle_is_refused_until_the_first_is_closed() {
        if std::env::var_os("PERMAURA_LOCK_TEST_CHILD").is_none() {
            // A parallel child test can fork while this handle is open and keep its lock until exec.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "lock::tests::a_second_handle_is_refused_until_the_first_is_closed", "--test-threads=1"])
                .env("PERMAURA_LOCK_TEST_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let path = std::env::temp_dir().join(format!("permaura-platform-lock-{}", std::process::id()));
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .unwrap()
        };
        let first = open();
        assert!(try_lock_exclusive(&first).unwrap());
        let second = open();
        assert!(!try_lock_exclusive(&second).unwrap(), "held by the first handle");
        drop(first);
        assert!(try_lock_exclusive(&second).unwrap(), "released when the holder closes");
        drop(second);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn the_lock_file_is_created_once_and_never_through_a_link() {
        let dir = std::env::temp_dir().join(format!("permaura-platform-lockfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.lock");
        let _ = std::fs::remove_file(&path);
        assert!(open_lock_file(&path, false).is_err(), "not created when not asked");
        let (_, created) = open_lock_file(&path, true).unwrap();
        assert!(created);
        let (_, created) = open_lock_file(&path, true).unwrap();
        assert!(!created, "opened, not created, the second time");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            let victim = dir.join("victim");
            std::fs::write(&victim, b"keep").unwrap();
            let link = dir.join("planted.lock");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            assert!(open_lock_file(&link, true).is_err(), "a planted link is refused");
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
