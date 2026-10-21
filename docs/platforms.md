# Platforms

Permaura's gateway (the `permaura` binary, and the `permaura` npm launcher that installs it) and the desktop app run on
macOS, Linux, and Windows across both arm64 and x86-64.

## Supported targets

| OS | Arch | Gateway | Desktop app |
|---|---|---|---|
| macOS | arm64 (Apple Silicon) | ✅ | ✅ (.dmg, universal) |
| macOS | x86-64 (Intel) | ✅ | ✅ (.dmg, universal) |
| Linux | x86-64 | ✅ (static musl) | ✅ (.deb, .AppImage) |
| Linux | arm64 | ✅ (static musl) | ❌ (use the gateway directly) |
| Windows | x86-64 | ✅ (MSVC) | ✅ (.exe NSIS, .msi) |
| Windows | arm64 | ✅ (MSVC) | ✅ (.exe NSIS), MSI is x64-only |

The gateway binary is downloaded and kept up to date by `permaura` (installed with `npm i -g permaura`), or bundled as a
sidecar inside the desktop app. Sidecars are pinned by sha256 against the signed release manifest at
build time on every platform, and additionally Apple-codesigned inside the macOS app bundle.

## Installer signing

| OS | Installer signing | What users see on first run |
|---|---|---|
| macOS | Developer ID + notarised | Nothing; opens normally |
| Windows | **Not yet signed** | SmartScreen "unknown publisher"; choose More info → Run anyway |
| Linux | Not signed (not required) | Nothing, or a routine confirmation prompt |

Windows Authenticode signing is in procurement. The in-app
updater verifies its own minisign signature on every platform regardless, so update integrity does
not depend on installer signing.

## Where Permaura keeps its files: `~/.permaura`

All persistent gateway state (the SQLite store `gateway.db`, the sealed vault, the relay worker
key `worker.key`, the audit signing key, and per-host config) lives under **one directory on every
platform**:

| Platform | `~/.permaura` resolves to |
|---|---|
| macOS / Linux | `$HOME/.permaura` |
| Windows | `%USERPROFILE%\.permaura` (e.g. `C:\Users\you\.permaura`) |

- The home directory is resolved with `dirs::home_dir()` (`$HOME` on Unix, the user-profile
  known-folder on Windows), so no configuration is needed.
- **Override:** set `PERMAURA_HOME` to relocate everything (e.g. onto a different volume). It is taken
  verbatim and wins over the default on every platform.
- Permaura deliberately does **not** use `%APPDATA%`/`%LOCALAPPDATA%` for this state: one rule, no
  per-OS migration. Logs are the exception: they follow each OS's convention
  (`~/Library/Logs/Permaura` on macOS, `%LOCALAPPDATA%\Permaura\logs` on Windows,
  `$XDG_STATE_HOME/permaura/logs` on Linux).
- Secrets (keys, the sealed DB) refuse to write if **no** home resolves and `PERMAURA_HOME` is unset,
  rather than falling back to the current directory: a missing home is an error, never a silent
  world-readable write into a repo.

## Windows notes

- **Command connectors:** a connector `program` is passed to the OS verbatim (no shell, no `PATHEXT`
  emulation). A bare `PATH` name only launches if it's a real `.exe` (`node`, `git`); a `.cmd`/`.bat`
  shim (`npm`, `yarn`, `vercel`) must be given explicitly as `vercel.cmd` or an absolute path. See
  [connector-authoring.md](./connector-authoring.md#command-connectors-on-windows).
- **Owner-only secret files:** on Unix the key files are created `0600`, and the database is narrowed
  to owner-only after SQLite creates it; on Windows the key files get a protected ACL with exactly two entries, the account the gateway runs as and `SYSTEM`,
  and no inherited entries.

## Linux desktop tray

The desktop app's tray icon needs a StatusNotifierItem host. KDE and most Ubuntu setups ship one, but
**stock GNOME requires the "AppIndicator and KStatusNotifierItem" extension** installed and enabled,
or the icon won't appear. If your session has no tray host, use "Launch at login" (autostart) and open
the popover window directly: the gateway runs headless regardless of whether the tray icon shows.

## WSL

Running the gateway inside WSL2 works like native Linux: it resolves `~/.permaura` under the WSL
home (`/home/<you>/.permaura`, a separate directory from the Windows-side `%USERPROFILE%\.permaura`),
binds `127.0.0.1:7376` inside the WSL network namespace, and updates via the Linux gateway binary.

- Reach a WSL-hosted gateway from a Windows browser/app at `http://127.0.0.1:7376`: recent WSL2
  forwards `localhost` automatically. If it doesn't, use the WSL VM's IP (`wsl hostname -I`).
- Run the gateway on **either** the Windows side **or** the WSL side, not both: they'd contend for
  port 7376. The desktop app is a native Windows app and supervises the Windows-side gateway.
- WSL is treated as native Linux and is not a separately certified target; the native Windows build is
  the supported path for Windows users.
