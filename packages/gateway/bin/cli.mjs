#!/usr/bin/env node
// permaura: the dead-easy way to run the Permaura gateway.
//   npx -y permaura start                 # install-or-upgrade, run, print the URL
//   PERMAURA_PAIR_CODE=PGW-XXXX npx -y permaura start # …and connect it to your permaura.com account
//   npx -y permaura status                # …or any other permaura command, against a running one
//   npx -y permaura upgrade               # just fetch the latest binary and exit
//   npx -y permaura                       # print this and start nothing
//
// Zero dependencies: it reads the release manifest, downloads the prebuilt binary from the public
// dist release, verifies its SHA-256, and runs it. Every run checks the manifest and swaps in a
// newer binary when one ships (skip with --no-upgrade / PERMAURA_NO_UPGRADE=1).
//
// This is a launcher, not a second CLI. Everything but the install/upgrade half is handed to the
// binary verbatim, so there is exactly one implementation of every command, including `--pair`,
// which the binary performs itself once it is up.
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import http from "node:http";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";

import {
  COMMANDS,
  DEFAULT_ADDR,
  exitExplanation,
  HEALTH_WAIT_SECS,
  platformKey,
  binaryFilename,
  reachableAddr,
  releaseTrustRoot,
  startAddr,
  stopWithCurrentToken,
  sweepOldBinaries,
  swapBinaryIntoPlace,
  upgradePlan,
  verifyDetachedSignatureAny,
} from "./lib.mjs";

// The single source of truth for "what's the latest gateway": a static JSON in the public dist repo.
// PERMAURA_MANIFEST_URL replaces it from a source checkout only; see releaseTrustRoot.
const DEFAULT_MANIFEST_URL =
  "https://raw.githubusercontent.com/pixelitemedia/permaura-dist/main/manifests/gateway.json";
const ADDR = process.env.PERMAURA_ADDR || DEFAULT_ADDR;
// The same `~/.permaura` the gateway itself resolves (PERMAURA_HOME override kept).
const DIR = process.env.PERMAURA_HOME || path.join(os.homedir(), ".permaura");
const BIN = path.join(DIR, "bin", binaryFilename(platformKey()));
// Where a clean-bootstrapping gateway drops the per-install operator bearer it just minted (0600).
// There is deliberately no constant fallback: a predictable token would be a public operator
// credential on the very gateway the user is about to put real secrets into.
const TOKEN_FILE = path.join(DIR, "operator.token");
// How long Ctrl-C waits for the gateway to exit before killing it: its drain window and last upload, then
// the tunnel and relay teardown. It goes on writing its store after it stops answering, so killing it
// sooner cuts off calls it is still recording. The same bound the desktop app waits.
const DRAIN_WAIT_MS = 15000;

const C = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
};
const ok = (s) => console.log(`${C.green("✓")} ${s}`);
const step = (s) => console.log(`${C.cyan("→")} ${s}`);
const warn = (s) => console.log(`${C.yellow("!")} ${s}`);

const KNOWN = new Set(COMMANDS);

/** The two global flags that take a value, so their value is never mistaken for the subcommand. */
const VALUE_FLAGS = new Set(["--url", "--token"]);

/**
 * How the reader should type this command back, which is not always how the help was written.
 *
 * The usage lines used to be a constant reading `npx -y permaura`, which is right for the route most
 * people arrive by and wrong for the other one that installs this file: `npm i -g permaura` puts the
 * launcher on PATH, and telling someone to reach it through npx then sends them back out to the
 * registry to fetch a copy of what they are already running. It is not in the docs, but it is the
 * reflex for anything published on npm, and it works, so the help has to know.
 *
 * npx runs the package out of its own cache (`~/.npm/_npx/<hash>/node_modules/permaura/bin/cli.mjs`),
 * so the path this module was loaded from is the answer; nothing else needs to be probed or asked.
 * Anything unrecognised falls to the bare name, because that is the harmless way to be wrong: a
 * reader on PATH gets a command that works, and an npx user gets one their shell will tell them
 * about immediately.
 *
 * The `curl | sh` route never reaches here at all: it installs the Rust binary, whose own clap help
 * has said `permaura <command>` throughout.
 */
function invocation() {
  const self = process.argv[1] ?? "";
  return self.includes(`${path.sep}_npx${path.sep}`) ? "npx -y permaura" : "permaura";
}

/** How to pass a pairing code on this platform's usual shell: in the environment, which keeps it out of the process list, since the POSIX `VAR=value command` form fails in PowerShell and cmd. */
function pairUsage(me, platform = process.platform) {
  const note = "                          …and connect it to your permaura.com account (the\n                          variable keeps the code out of the process list)";
  if (platform === "win32") {
    return `  $env:PERMAURA_PAIR_CODE="PGW-XXXX"; ${me} start         (PowerShell)\n  set "PERMAURA_PAIR_CODE=PGW-XXXX" && ${me} start      (cmd)\n${note}`;
  }
  return `  PERMAURA_PAIR_CODE=PGW-XXXX ${me} start\n${note}`;
}

/** The `permaura pair` line to suggest for a gateway at `addr`, with the code in the environment the way this platform's shell sets it. */
function pairHint(addr, platform = process.platform) {
  if (platform === "win32") {
    return `$env:PERMAURA_PAIR_CODE="<code>"; permaura pair --url http://${addr}   (cmd: set "PERMAURA_PAIR_CODE=<code>" && permaura pair --url http://${addr})`;
  }
  return `PERMAURA_PAIR_CODE=<code> permaura pair --url http://${addr}`;
}

const usage = (me = invocation()) => `permaura: the dead-easy way to run the Permaura gateway.

Usage:
  ${me} start                  install-or-upgrade, run, print the URL
${pairUsage(me)}
  ${me} upgrade                 just fetch the latest binary and exit
  ${me} <command> [args…]       run any other permaura command against a gateway
  ${me} --version               print the launcher + installed-binary versions
  ${me} --help                  print this

Commands (${[...KNOWN].sort().join(", ")}) are the binary's own: run
\`${me} help <command>\` for one of them.

Launcher options:
  --no-upgrade    run the cached binary without checking for a newer one
                  (same as PERMAURA_NO_UPGRADE=1)
  --version, -v   print versions and exit
  --help, -h      print this and exit

Environment:
  PERMAURA_HOME       where the binary, store and operator token live (default ~/.permaura)
  PERMAURA_ADDR       address the gateway binds (default 127.0.0.1:7376; start --addr overrides it)
  PERMAURA_API        account API base (default https://permaura.com; a release gateway honors only a loopback address)
  PERMAURA_NO_UPGRADE set to 1 to skip the upgrade check
`;

/**
 * Work out what this invocation is: which subcommand (if any), and which of the launcher's own flags
 * were given before it.
 *
 * NO arguments prints help and starts nothing. A multi-command tool that boots a long-running server
 * when invoked bare is a surprise, and this is the first command most people type. An unrecognised
 * subcommand is an ERROR for the same reason it always was: `--help`, and every typo, used to
 * silently boot a gateway and bind a port.
 *
 * Everything else is forwarded to the binary untouched (minus the launcher-only flags), so the
 * binary's own parser owns global flags, per-command flags and `--help` after a subcommand.
 */
function parseArgs(argv) {
  let cmd = null;
  let cmdAt = -1;
  let noUpgrade = process.env.PERMAURA_NO_UPGRADE === "1";
  let showVersion = false;
  let showHelp = false;
  const forward = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (VALUE_FLAGS.has(a)) {
      forward.push(a);
      if (i + 1 < argv.length) forward.push(argv[++i]);
      continue;
    }
    if (a === "--no-upgrade") {
      // Launcher-only: the binary has never heard of it, so it must not be forwarded.
      noUpgrade = true;
      continue;
    }
    if (!cmd && (a === "--version" || a === "-v")) {
      showVersion = true;
      continue;
    }
    if (!cmd && (a === "--help" || a === "-h")) {
      showHelp = true;
      continue;
    }
    if (!cmd && !a.startsWith("-")) {
      cmd = a;
      cmdAt = forward.length;
    }
    forward.push(a);
  }
  return { cmd, cmdAt, forward, noUpgrade, showVersion, showHelp };
}

/** This package's own version, read from the sibling package.json. */
function cliVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    return pkg.version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/** The installed binary's version (`permaura-gateway 0.1.1` → `0.1.1`), or null if absent/unreadable. */
function installedVersion() {
  if (!fs.existsSync(BIN)) return null;
  try {
    const out = spawnSync(BIN, ["--version"], { encoding: "utf8", timeout: 5000 });
    const m = /(\d+\.\d+\.\d+[^\s]*)/.exec(out.stdout || "");
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/** https normally; plain http honoured so a PERMAURA_MANIFEST_URL override can point at a local test server (the release smoke does). */
function requester(u) {
  return u.startsWith("http://") ? http : https;
}

function httpGet(url, { json = false } = {}) {
  return new Promise((resolve, reject) => {
    const go = (u, redirects = 0) => {
      requester(u)
        .get(u, { headers: { "User-Agent": "permaura-gateway-cli" } }, (res) => {
          if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
            res.resume();
            if (redirects > 10) return reject(new Error("too many redirects"));
            return go(res.headers.location, redirects + 1);
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`HTTP ${res.statusCode} for ${u}`));
          }
          const chunks = [];
          res.on("data", (d) => chunks.push(d));
          res.on("end", () => {
            const buf = Buffer.concat(chunks);
            if (json) {
              try {
                resolve(JSON.parse(buf.toString("utf8")));
              } catch (e) {
                reject(new Error(`bad manifest JSON: ${e.message}`));
              }
            } else {
              resolve(buf);
            }
          });
        })
        .on("error", reject);
    };
    go(url);
  });
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const go = (u, redirects = 0) => {
      requester(u)
        .get(u, { headers: { "User-Agent": "permaura-gateway-cli" } }, (res) => {
          if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
            res.resume();
            if (redirects > 10) return reject(new Error("too many redirects"));
            return go(res.headers.location, redirects + 1);
          }
          if (res.statusCode !== 200) {
            res.resume();
            return reject(new Error(`download failed: HTTP ${res.statusCode}`));
          }
          const file = fs.createWriteStream(dest);
          res.pipe(file);
          file.on("finish", () => file.close(() => resolve()));
          file.on("error", (e) => reject(e));
        })
        .on("error", reject);
    };
    go(url);
  });
}

function sha256File(p) {
  return crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

/**
 * The release signing keys this launcher accepts (Ed25519, SPKI PEM), newest first.
 *
 * Why this matters: `asset.sha256` comes from the SAME manifest as `asset.url`. That is integrity
 * against a corrupted download, not authenticity: anyone who can change the manifest changes both
 * numbers and the checksum cheerfully confirms their binary. Only a signature made by a key we pinned
 * out-of-band says "Permaura built this".
 *
 * Why a LIST. A launcher installed with `npm i -g` is not replaced by the release manifest the way the
 * gateway binary is, so whatever is pinned here sits on people's machines until they think to run
 * `npm update -g permaura`. With one key, rotating it breaks every one of those installs at once, and
 * the break is unrecoverable from the client side: the thing that would carry the new key is itself
 * signed with it. A set gives rotation an overlap window. The shape is: add
 * the next key here, ship, wait, and only then sign with it.
 *
 * MUST stay in step with the other three pin sites, or an install verifies on one surface and fails on
 * another:
 *   services/gateway/src/release.rs            → RELEASE_PUBKEY_PEMS
 *   the desktop app's binary updater           → RELEASE_PUBKEY_PEMS
 *   permaura.com's install route               → RELEASE_PUBKEY_PEMS
 *
 * `PERMAURA_RELEASE_PUBKEY` replaces the whole set with one key, which is how the tests drive a
 * throwaway one, and only from a source checkout (releaseTrustRoot): in a published launcher the
 * environment would otherwise name the key the binary it installs is checked against.
 */
const PINNED_RELEASE_PUBKEY_PEMS = [
  // pmrel-2026a, generated 2026-08-03.
  `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAKqPdId97cJ1iXDNMq767UseY9eMKe7jBSOKNzjQp76Q=
-----END PUBLIC KEY-----`,
];

// The published package carries bin/ alone, so test/ beside it marks a source checkout.
const TRUST = releaseTrustRoot({
  env: process.env,
  sourceCheckout: fs.existsSync(new URL("../test/", import.meta.url)),
  pinnedKeys: PINNED_RELEASE_PUBKEY_PEMS,
  manifestUrl: DEFAULT_MANIFEST_URL,
});
for (const name of TRUST.ignored) {
  console.error(`permaura: ${name} is set and ignored: a published launcher trusts only the pinned release key and manifest.`);
}
const MANIFEST_URL = TRUST.manifestUrl;
const RELEASE_PUBKEY_PEMS = TRUST.keys;

/** With a key configured, a valid signature is REQUIRED. Without one, we cannot verify anything yet. */
const REQUIRE_SIGNATURE = RELEASE_PUBKEY_PEMS.length > 0;

/**
 * Verify a detached Ed25519 signature over the EXACT manifest bytes.
 *
 * Detached-over-raw-bytes on purpose: signing a field *inside* the JSON would mean canonicalising it
 * first, and every canonicalisation bug is a signature bypass. The bytes we verify are the bytes we
 * parse.
 *
 * Returns true when verified, false when no key is configured (nothing to verify against), and throws
 * when a key IS configured and the signature is missing or bad: that is an attack, not a hiccup.
 */
async function verifyManifestSignature(rawManifest, sigUrl) {
  if (!REQUIRE_SIGNATURE) return false;

  let sigB64;
  try {
    sigB64 = (await httpGet(sigUrl)).toString("utf8").trim();
  } catch (e) {
    throw new Error(
      `the release manifest is not signed (${e.message}). Refusing to install: a signature is required once a release key is pinned.`,
    );
  }

  // The crypto itself lives in lib.mjs so it is testable without a network; it throws on every failure.
  return verifyDetachedSignatureAny(rawManifest, sigB64, RELEASE_PUBKEY_PEMS);
}

/**
 * Ensure `BIN` is present and (unless suppressed) up to date with the manifest. Returns the version
 * now installed. `force` re-downloads even when the versions match (the explicit `upgrade` command).
 *
 * Failure modes never leave the user worse off: if the manifest can't be fetched but a binary is
 * already cached, we keep running the cached one; only a first install with no network is fatal.
 */
async function ensureBinary({ noUpgrade, force }) {
  const key = platformKey();
  if (!key) {
    throw new Error(
      `unsupported platform ${process.platform}/${process.arch}: prebuilt gateways cover macOS, Linux and Windows on arm64/x64. https://permaura.com/docs`,
    );
  }
  fs.mkdirSync(path.join(DIR, "bin"), { recursive: true });

  // Sweep binaries parked by a previous rename-aside upgrade (cleanup on start; no-op when no
  // live binary exists: a lone .old may be the only working copy after a failed swap).
  sweepOldBinaries(BIN);

  const have = installedVersion();
  const haveBinary = fs.existsSync(BIN);

  let manifest;
  let manifestVerified = false;
  try {
    // Fetch the RAW bytes so the signature covers exactly what we parse (see verifyManifestSignature).
    const rawManifest = await httpGet(MANIFEST_URL);
    manifestVerified = await verifyManifestSignature(rawManifest, `${MANIFEST_URL}.sig`);
    try {
      manifest = JSON.parse(rawManifest.toString("utf8"));
    } catch (e) {
      throw new Error(`bad manifest JSON: ${e.message}`);
    }
  } catch (e) {
    // A signature failure is never "the network was flaky": it must not fall back to a cached binary
    // and carry on as though nothing happened.
    if (REQUIRE_SIGNATURE && /signature|signed|release key/i.test(e.message)) throw e;
    if (haveBinary && !force) {
      warn(`Couldn't check for updates (${e.message}); using the cached gateway${have ? ` ${have}` : ""}.`);
      return have;
    }
    throw new Error(`could not fetch the release manifest: ${e.message}`);
  }
  if (!REQUIRE_SIGNATURE) {
    warn(
      "This build cannot verify that the gateway binary came from Permaura: no release key is pinned yet. The download is checksummed, but a checksum from an unsigned manifest only proves the file arrived intact, not who made it.",
    );
  }

  const asset = manifest?.assets?.[key];
  if (!asset?.url) {
    if (haveBinary && !force) {
      warn(`Manifest has no ${key} build; using the cached gateway${have ? ` ${have}` : ""}.`);
      return have;
    }
    throw new Error(`the manifest has no build for ${key}`);
  }

  const latest = manifest.version;
  const floor = cliVersion();
  const plan = upgradePlan({ installed: have, latest, haveBinary, force, floor });
  if (plan === "older") {
    warn(`The release manifest names ${latest}, older than the installed ${have}. Keeping ${have}: the launcher never installs an older gateway.`);
    return have;
  }
  if (plan === "stale") {
    const why = `The release manifest names ${latest}, older than this launcher (${floor}). A signed manifest older than the launcher that fetched it is a replayed release or one still being published, so it is not installed.`;
    if (haveBinary) {
      warn(`${why} Keeping the cached gateway${have ? ` ${have}` : ""}.`);
      return have;
    }
    throw new Error(`${why} Retry in a few minutes; if it persists, report it to security@permaura.com.`);
  }
  if (plan === "current") {
    ok(noUpgrade ? `Using cached gateway ${have} (upgrade check skipped).` : `Gateway ${have} is up to date.`);
    return have;
  }
  if (noUpgrade && haveBinary) {
    warn(`A newer gateway (${latest}) is available; skipping because --no-upgrade.`);
    return have;
  }

  step(
    haveBinary
      ? `Updating the gateway ${have ?? "?"} → ${latest} (${key})…`
      : `Downloading the Permaura gateway ${latest} (${key})…`,
  );
  const tmp = `${BIN}.download`;
  await download(asset.url, tmp);

  // Fail closed on a missing checksum. Warning and installing anyway made the one check we DO have
  // optional at the attacker's discretion: strip the sha256 field and the guard politely stands aside.
  if (!asset.sha256) {
    fs.rmSync(tmp, { force: true });
    throw new Error(
      `the manifest has no sha256 for ${key}, so the download cannot be checked. Refusing to install an unverifiable binary.`,
    );
  }
  const got = sha256File(tmp);
  if (got.toLowerCase() !== String(asset.sha256).toLowerCase()) {
    fs.rmSync(tmp, { force: true });
    throw new Error(`checksum mismatch for the downloaded binary (expected ${asset.sha256}, got ${got})`);
  }

  fs.chmodSync(tmp, 0o755);
  // Rename-aside swap (the rustup pattern): park the current binary at `.old`, move the verified
  // download into place, restore the parked copy if that fails: a runnable binary exists at BIN on
  // every exit path. A gateway already running the old inode keeps working on every platform; the
  // sweep above collects parked files on a later run.
  swapBinaryIntoPlace(BIN, tmp);
  // Quarantine is macOS's own "you didn't make this" flag, so stripping it from an artifact we could
  // not authenticate throws away the last check standing. Once a release key is pinned this only runs
  // for a signature-verified binary; until then it must still run, because the gateway binary is not
  // notarized and Gatekeeper would otherwise refuse to execute it at all: removing the strip today
  // would simply break every macOS install. Un-gating it is part of the signing work, not separate
  // from it.
  if (process.platform === "darwin" && (manifestVerified || !REQUIRE_SIGNATURE)) {
    try {
      spawnSync("xattr", ["-d", "com.apple.quarantine", BIN], { stdio: "ignore" });
    } catch {
      /* not fatal */
    }
  }
  ok(`Installed gateway ${latest} to ${BIN}`);
  return latest;
}

/**
 * The operator bearer for this install: an explicit PERMAURA_TOKEN, else the one the gateway minted
 * into `operator.token` on clean bootstrap. Returns null when neither exists: a gateway initialised
 * by an older build has a bearer we can't read, and inventing a shared one is exactly the hole this
 * closes. Callers degrade to manual pairing instead.
 */
function readOperatorToken() {
  if (process.env.PERMAURA_TOKEN) return process.env.PERMAURA_TOKEN;
  try {
    return fs.readFileSync(TOKEN_FILE, "utf8").trim() || null;
  } catch {
    return null;
  }
}

function health(addr) {
  return new Promise((resolve) => {
    let req;
    try {
      req = http.get(`http://${addr}/health`, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
    } catch {
      // An address no URL can hold is one the binary refuses too; its own error and exit code should be what the user sees.
      return resolve(false);
    }
    req.on("error", () => resolve(false));
    req.setTimeout(1500, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitHealthz(addr, seconds = HEALTH_WAIT_SECS) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    if (await health(addr)) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

async function main() {
  const { cmd, cmdAt, forward, noUpgrade, showVersion, showHelp } = parseArgs(process.argv.slice(2));

  if (showHelp) {
    console.log(usage());
    return;
  }

  if (showVersion) {
    console.log(`permaura (launcher) ${cliVersion()}`);
    const have = installedVersion();
    console.log(`permaura (binary) ${have ?? "(not installed)"}`);
    return;
  }

  if (!cmd) {
    if (forward.length) {
      // Arguments but no command: a mistyped flag. It must not fall through to the bare-invocation
      // help and exit 0, and it certainly must not start anything.
      console.error(`${C.red("✗")} unknown argument${forward.length > 1 ? "s" : ""}: ${forward.join(", ")}\n`);
      console.error(usage());
      process.exitCode = 2;
      return;
    }
    // Bare `permaura`: say what it does, start nothing.
    console.log(usage());
    return;
  }

  if (!KNOWN.has(cmd)) {
    // Exit before anything binds a port or downloads a binary: a mistyped command should cost
    // nothing.
    console.error(`${C.red("✗")} unknown command: ${cmd}\n`);
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  if (cmd === "upgrade") {
    const v = await ensureBinary({ noUpgrade: false, force: true });
    ok(`permaura is at ${v}.`);
    return;
  }

  await ensureBinary({ noUpgrade, force: false });

  // Everything that is not `start` is a short-lived command against a gateway: hand it straight to
  // the binary, share this terminal, and exit with whatever it exits with.
  if (cmd !== "start") {
    const child = spawn(BIN, forward, { stdio: "inherit" });
    child.on("exit", (code, signal) => process.exit(signal ? 1 : (code ?? 0)));
    child.on("error", (e) => {
      console.error(`${C.red("✗")} could not run ${BIN}: ${e.message}`);
      process.exit(1);
    });
    return;
  }

  // PERMAURA_ADDR is the launcher's default bind; an explicit `--addr` in `forward` still wins,
  // because clap ranks a flag above its env fallback, so everything below watches what the child binds.
  const bind = startAddr(forward.slice(cmdAt + 1), { PERMAURA_ADDR: ADDR });
  const addr = reachableAddr(bind);
  step(`Starting gateway at http://${bind}…`);
  const child = spawn(BIN, forward, {
    env: { ...process.env, PERMAURA_ADDR: ADDR },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => process.stdout.write(C.dim(d.toString())));
  child.stderr.on("data", (d) => process.stderr.write(C.dim(d.toString())));
  child.on("exit", (code) => {
    console.log(`gateway exited (${code ?? 0})`);
    const why = exitExplanation(code);
    if (why) console.error(`${C.red("✗")} ${why}`);
    process.exit(code ?? 0);
  });

  if (!(await waitHealthz(addr))) {
    console.error(`${C.red("✗")} the gateway did not become healthy at http://${addr}`);
    child.kill();
    process.exit(1);
  }
  ok(`Gateway running at http://${addr}`);

  const token = readOperatorToken();
  // The child inherits PERMAURA_PAIR_CODE and pairs from it, the form the docs give, as surely as from --pair.
  const pairing = forward.some((a) => a === "--pair" || a.startsWith("--pair=")) || Boolean(process.env.PERMAURA_PAIR_CODE);
  if (!token) {
    // The gateway is up and healthy: only adding it to an account needs the bearer. Say so plainly
    // rather than guessing at a token.
    warn(
      `This gateway was initialised by an earlier build, so its operator token isn't readable here.\n    To pair it, run \`permaura pair --url http://${addr}\` with PERMAURA_PAIR_CODE=<code> and PERMAURA_TOKEN=<token> set.`,
    );
  } else if (!pairing) {
    // With --pair the binary reports the enrolment itself, success or failure, and prints this when
    // it fails. The token is never printed: this output lands in CI logs and shared terminals.
    console.log(
      `\nTo connect it to your permaura.com account, get a pairing code from Connect a gateway in the console, then run:\n    ${pairHint(addr)}`,
    );
  }

  console.log(C.dim("\nGateway is running. Press Ctrl-C to stop."));
  process.on("SIGINT", async () => {
    // Graceful first: /v1/shutdown lets the gateway drain and exit cleanly. This matters most on
    // Windows, where child.kill() is an abrupt TerminateProcess; on Unix the foreground Ctrl-C
    // already reached the child too, so this is belt-and-braces. The child's exit handler ends the
    // process; the unref'd timer hard-kills if draining wedges. Without a readable token, or when the
    // listener does not prove it holds it, nothing is sent and the signal goes to our own child. The
    // token is read again here: the gateway may have rotated it since it started.
    const accepted = await stopWithCurrentToken(addr, readOperatorToken);
    if (!accepted) child.kill("SIGINT");
    setTimeout(() => {
      child.kill();
      process.exit(0);
    }, DRAIN_WAIT_MS).unref();
  });
}

main().catch((e) => {
  console.error(C.red("✗"), e.message);
  process.exit(1);
});
