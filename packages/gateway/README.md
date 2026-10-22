# permaura

Run the [Permaura](https://permaura.com) gateway with one command. **Give your AI agents permission, not keys.**

```bash
# Install once. `permaura` is then on your PATH, on macOS, Linux and Windows alike:
npm i -g permaura
permaura start

# Or connect it to your account (grab the pairing code from permaura.com, Connect a gateway):
PERMAURA_PAIR_CODE=PGW-XXXXXXXXXX permaura start
#   Windows PowerShell:  $env:PERMAURA_PAIR_CODE = "PGW-XXXXXXXXXX"; permaura start
#   Windows cmd:         set "PERMAURA_PAIR_CODE=PGW-XXXXXXXXXX" && permaura start

# Drive the gateway you just started:
permaura status
permaura grant --agent my-agent --resource db1 --allow uptime
permaura stop

# Just fetch the latest binary and exit, or print versions:
permaura upgrade
permaura --version
```

`permaura` on its own prints the help and starts nothing. Starting a gateway is always `start`.

It downloads the prebuilt binary (to `~/.permaura/bin/permaura`), starts it on `http://127.0.0.1:7376`, and, with `--pair`, enrolls it against your permaura.com account so your console goes live automatically. No copy/paste of URLs or tokens.

This package is a launcher, not a second CLI: every command other than `start` and `upgrade` is handed to the binary untouched, so `permaura <anything>` is the same program you get from the install script.

Every run checks the release manifest and swaps in a newer **gateway** when one ships (the manifest's Ed25519 signature is verified against a pinned release key, the download against the SHA-256 in it, and the swap is atomic so a running gateway is never disturbed). Pass `--no-upgrade` (or set `PERMAURA_NO_UPGRADE=1`) to pin the cached binary.

The **launcher** is the one thing that does not update itself, because npm owns it. Refresh it with `npm update -g permaura`.

Press **Ctrl-C** to stop a gateway running in the foreground.

## Other ways to install

Same gateway, same `~/.permaura`, different delivery. Pick whichever suits the machine.

```bash
# No Node at all, and it can set itself up to survive a reboot. macOS and Linux:
curl -fsSL https://permaura.com/install | sh
curl -fsSL https://permaura.com/install | PERMAURA_PAIR_CODE=PGW-XXXXXXXXXX sh

# Nothing installed, for a one-off or a throwaway box. Slowest, and nothing is left on your PATH:
npx -y permaura start
```

The install script fetches the binary directly, so it needs no Node and is the right choice for a server. `npx` is the one to reach for when you want to try the gateway without installing anything, or when you are scripting a machine you will not keep.

### Environment overrides

| Var | Default | Purpose |
|---|---|---|
| `PERMAURA_ADDR` | `127.0.0.1:7376` | address the gateway listens on |
| `PERMAURA_API` | `https://permaura.com` | account/pairing endpoint; a release build of the gateway honors only a loopback address (`http://127.0.0.1:<port>`), for local test stubs |
| `PERMAURA_NO_UPGRADE` | (unset) | set to `1` to skip the auto-upgrade check |

The release manifest and the key it is verified against are pinned. `PERMAURA_MANIFEST_URL` and `PERMAURA_RELEASE_PUBKEY` are honored only when the launcher runs from a source checkout (and by a debug build of the gateway), for the tests; the published launcher ignores them and says so.

macOS, Linux and Windows, on arm64 and x64.

> The gateway is a single self-contained binary. Source: https://github.com/permaura/permaura. Releases: https://github.com/permaura/permaura-dist
