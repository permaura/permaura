// Helpers shared by cli.mjs and the test suite. The naming/version helpers are pure; the
// swap/sweep helpers take an injectable fs so their failure paths are table-testable under
// `node --test` (a rename that fails mid-swap can't be provoked with the real fs).

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

/**
 * The manifest asset key for a platform/arch pair: darwin|linux|win32 × arm64|amd64.
 * Node reports x64 where the manifest says amd64 (the release matrix keeps the Go-style
 * `amd64` convention). Returns null for anything we don't ship.
 */
export function platformKey(platform = process.platform, arch = process.arch) {
  const os = { darwin: "darwin", linux: "linux", win32: "win32" }[platform];
  const cpu = { arm64: "arm64", x64: "amd64" }[arch];
  return os && cpu ? `${os}-${cpu}` : null;
}

/** The installed binary's filename for a manifest key: `.exe` on Windows, bare elsewhere. */
export function binaryFilename(key) {
  return key && key.startsWith("win32-") ? "permaura.exe" : "permaura";
}

/**
 * The release asset name for a manifest key (what CI stages and the manifest URLs point at):
 * `permaura-<key>`, plus `.exe` for Windows so the download is double-click-safe.
 */
export function assetName(key) {
  const suffix = key && key.startsWith("win32-") ? ".exe" : "";
  return `permaura-${key}${suffix}`;
}

/**
 * The binary's top-level subcommands, as clap names them, plus clap's own `help`. A command outside this list is refused before anything downloads a binary or binds a port, so a typo costs nothing; test/command-parity.test.mjs holds it to the binary's cli/mod.rs, so a command added there fails the suite until it is added here.
 */
export const COMMANDS = Object.freeze([
  "start",
  "stop",
  "uninstall",
  "pair",
  "upgrade",
  "auth",
  "remote",
  "advertise",
  "announce",
  "link",
  "unlink",
  "init",
  "status",
  "agent",
  "grant",
  "audit",
  "pending",
  "approve",
  "deny",
  "vault",
  "policy",
  "connection",
  "approver",
  "help",
]);

/**
 * How long the launcher waits for a started gateway to answer `/health`. Longer than the 20 s a start waits for another process to let this home's store go (`STORE_LOCK_WAIT` in the gateway) plus its boot, so a start waiting out a draining predecessor is not killed while it waits.
 */
export const HEALTH_WAIT_SECS = 40;

/** The gateway's exit when another process holds this home's store. */
export const EXIT_STORE_HELD = 73;

/** The gateway's exit when its store holds a signed audit chain and `gateway.db.auditkey` is gone. */
export const EXIT_AUDIT_KEY_MISSING = 74;

/**
 * What a gateway exit code means, for the codes that name a store problem a person can act on; `null` for any other code.
 */
export function exitExplanation(code) {
  if (code === EXIT_STORE_HELD) {
    return "another Permaura gateway holds this home's store, so this one did not open it. Stop the other one first (`permaura stop`), or give this gateway its own PERMAURA_HOME.";
  }
  if (code === EXIT_AUDIT_KEY_MISSING) {
    return "this home's gateway.db.auditkey is gone, so its signed audit history cannot be continued. Restore that file from the backup that holds gateway.db, or run `permaura audit rekey --yes` to start a new signing key that keeps every connection, credential, grant and agent.";
  }
  return null;
}

/** Where `permaura start` binds when neither `--addr` nor PERMAURA_ADDR says otherwise. */
export const DEFAULT_ADDR = "127.0.0.1:7376";

/**
 * The address `permaura start <args>` binds, by the binary's own precedence: `--addr` (either form), then PERMAURA_ADDR, then the default. `args` are the ones after `start`.
 */
export function startAddr(args, env = process.env) {
  let flag = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a === "--addr" && i + 1 < args.length) flag = args[++i];
    else if (a.startsWith("--addr=")) flag = a.slice("--addr=".length);
  }
  return flag ?? (env.PERMAURA_ADDR || DEFAULT_ADDR);
}

/** The address to reach a gateway bound at `bind` from this machine: an all-interfaces bind answers on loopback, at the same port. */
export function reachableAddr(bind) {
  const i = bind.lastIndexOf(":");
  const host = bind.slice(0, i);
  if (host === "0.0.0.0") return `127.0.0.1${bind.slice(i)}`;
  if (/^\[[0:]+\]$/.test(host)) return `[::1]${bind.slice(i)}`;
  return bind;
}

/**
 * Sweep binaries parked by a previous rename-aside upgrade (cleanup on start). Only sweeps when
 * a live binary exists at `binPath`: after a failed swap the newest `.old` may be the only working
 * copy on disk, and it must survive until a later successful swap replaces it. Best-effort: on
 * Windows a still-running old gateway keeps its file locked and is collected on a later run.
 */
export function sweepOldBinaries(binPath, fsOps = fs) {
  if (!fsOps.existsSync(binPath)) return;
  const dir = path.dirname(binPath);
  const base = path.basename(binPath);
  for (const f of fsOps.readdirSync(dir)) {
    if (f.startsWith(`${base}.old`)) {
      try {
        fsOps.rmSync(path.join(dir, f), { force: true });
      } catch {
        /* locked by a running process, leave it for next time */
      }
    }
  }
}

/**
 * Rename-aside swap (the rustup pattern): park the current binary at `.old` (Windows can't
 * overwrite a running executable but CAN rename it), then move the verified download into place.
 * If that final rename fails, the parked binary is restored: there is a runnable binary at
 * `binPath` on every exit path, success or throw.
 */
export function swapBinaryIntoPlace(binPath, tmpPath, fsOps = fs) {
  const oldPath = `${binPath}.old`;
  let parkedAt = null;
  if (fsOps.existsSync(binPath)) {
    try {
      fsOps.rmSync(oldPath, { force: true });
      fsOps.renameSync(binPath, oldPath);
      parkedAt = oldPath;
    } catch {
      // `.old` itself is a locked running binary: park under a unique name instead.
      const unique = `${binPath}.old-${Date.now()}`;
      fsOps.renameSync(binPath, unique);
      parkedAt = unique;
    }
  }
  try {
    fsOps.renameSync(tmpPath, binPath);
  } catch (e) {
    if (parkedAt) {
      try {
        fsOps.renameSync(parkedAt, binPath);
      } catch {
        /* restore failed: surface the original swap error below */
      }
    }
    throw e;
  }
}

/**
 * Compare versions by semver precedence. `<0` if a<b, `0` equal, `>0` if a>b.
 *
 * The pre-release suffix is part of the order, not noise to be discarded. It used to be dropped, so
 * `1.2.5-dev.1` compared EQUAL to the released `1.2.5` and the upgrade was never offered: a
 * dev build of a version permanently masked that version's real release, on exactly the machines
 * most likely to be running one.
 */
export function compareVersions(a, b) {
  const split = (v) => {
    const s = String(v ?? "0").replace(/^v/, "");
    const i = s.indexOf("-");
    return i === -1 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)];
  };
  const [coreA, preA] = split(a);
  const [coreB, preB] = split(b);
  const nums = (c) => c.split(".").map((n) => parseInt(n, 10) || 0);
  const pa = nums(coreA);
  const pb = nums(coreB);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return comparePreRelease(preA, preB);
}

/**
 * What to do with the version a verified manifest names: `"install"` it, leave the `"current"` binary, or refuse it as `"older"` (than what is installed) or `"stale"` (below `floor`).
 *
 * Never older than what is installed, the explicit `upgrade` included: manifests carry no expiry or sequence number, so an old manifest with a genuine signature is exactly what a rollback would serve. `floor` covers the case with nothing installed to compare against: the launcher passes its own npm version, which reaches the user over a channel the manifest's signer cannot move. `force` only reinstalls the same version, as a repair.
 */
export function upgradePlan({ installed, latest, haveBinary, force = false, floor = null }) {
  if (haveBinary && installed && compareVersions(latest, installed) < 0) return "older";
  if (floor && compareVersions(latest, floor) < 0) return "stale";
  if (force || !haveBinary || !installed || compareVersions(installed, latest) < 0) return "install";
  return "current";
}

/**
 * Semver §11.4 precedence for the pre-release part, over equal numeric cores.
 *
 * A version WITH a pre-release ranks below the same version without one; between two of them,
 * identifiers are compared dot-by-dot, numerically when both are numeric, and a numeric identifier
 * ranks below an alphanumeric one. A shorter run of identifiers loses when it is a prefix of the
 * longer, which is what makes `1.0.0-rc` older than `1.0.0-rc.1`.
 */
function comparePreRelease(a, b) {
  if (a === b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  const ia = a.split(".");
  const ib = b.split(".");
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    const x = ia[i];
    const y = ib[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const d = parseInt(x, 10) - parseInt(y, 10);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (xNum !== yNum) {
      return xNum ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * The manifest source and release keys the launcher trusts, and the overrides it ignored.
 * `PERMAURA_MANIFEST_URL` and `PERMAURA_RELEASE_PUBKEY` are how the tests and the release smoke drive
 * a loopback channel and a throwaway key, so they are honored from a source checkout only. A published
 * launcher ignores them: whatever can set its environment (a shell profile, a project's settings, a
 * wrapper) could otherwise have it install a binary signed by a key of its own choosing.
 */
export function releaseTrustRoot({ env = process.env, sourceCheckout, pinnedKeys, manifestUrl }) {
  const url = (env.PERMAURA_MANIFEST_URL ?? "").trim();
  const key = (env.PERMAURA_RELEASE_PUBKEY ?? "").trim();
  const ignored = sourceCheckout
    ? []
    : [url && "PERMAURA_MANIFEST_URL", key && "PERMAURA_RELEASE_PUBKEY"].filter(Boolean);
  return {
    manifestUrl: sourceCheckout && url ? url : manifestUrl,
    keys: sourceCheckout && key ? [key] : pinnedKeys,
    ignored,
  };
}

/**
 * Verify a detached Ed25519 signature over the EXACT bytes of a release manifest, against ANY of the
 * keys we accept.
 *
 * Detached-over-raw-bytes on purpose: signing a field *inside* the JSON would mean canonicalising the
 * document first, and canonicalisation bugs are signature bypasses. The bytes verified here are the
 * bytes the caller parses.
 *
 * **Why a list rather than one key.** A single pinned key cannot be rotated. Sign with a new key and
 * every client pinned to the old one rejects the manifest, permanently and with no way back, because
 * the thing that would tell them about the new key is itself signed. Accepting a set gives rotation an
 * overlap: ship a build that accepts both, wait for it to reach people, and only then start signing
 * with the new one. The list is the mechanism, so it has to exist BEFORE the key it will carry.
 *
 * Every key is parsed up front, so a malformed pin fails loudly in the tests rather than silently
 * shrinking the accepted set in a shipped artifact. The signature's own shape is checked once, since
 * a wrong length is malformed whichever key you hold and reporting it as "no key matched" would send
 * the reader hunting for a key problem they do not have.
 *
 * Throws on every failure rather than returning false, so a caller cannot accidentally treat an
 * unverified manifest as verified by ignoring a return value.
 */
export function verifyDetachedSignatureAny(rawBytes, sigB64, publicKeyPems) {
  const pems = (Array.isArray(publicKeyPems) ? publicKeyPems : [publicKeyPems])
    .map((p) => String(p ?? "").trim())
    .filter((p) => p.length > 0);
  if (pems.length === 0) {
    throw new Error("no release key is pinned, so nothing can be verified");
  }

  const keys = pems.map((pem) => {
    let key;
    try {
      key = crypto.createPublicKey(pem);
    } catch (e) {
      throw new Error(`the pinned release key is not a valid public key: ${e.message}`);
    }
    if (key.asymmetricKeyType !== "ed25519") {
      // Guards against a pinned key of the wrong type quietly selecting a different algorithm.
      throw new Error(`the pinned release key must be ed25519, got ${key.asymmetricKeyType}`);
    }
    return key;
  });

  let sig;
  try {
    sig = Buffer.from(String(sigB64).trim(), "base64");
  } catch {
    throw new Error("the manifest signature is not valid base64");
  }
  // Ed25519 signatures are exactly 64 bytes; a wrong length is malformed, not merely invalid.
  if (sig.length !== 64) {
    throw new Error(`the manifest signature is malformed (expected 64 bytes, got ${sig.length})`);
  }

  const raw = Buffer.from(rawBytes);
  // Ed25519 verifies in one shot: algorithm null, no pre-hashing.
  if (keys.some((key) => crypto.verify(null, raw, key, sig))) return true;

  throw new Error(
    keys.length === 1
      ? "the release manifest's signature did not verify against the pinned Permaura release key"
      : `the release manifest's signature did not verify against any of the ${keys.length} pinned Permaura release keys`,
  );
}

/** One key, for callers that hold exactly one. Kept so the single-key call sites read plainly. */
export function verifyDetachedSignature(rawBytes, sigB64, publicKeyPem) {
  return verifyDetachedSignatureAny(rawBytes, sigB64, [publicKeyPem]);
}

// ── Proof that the listener holds the operator token ────────────────────────────────────────────
//
// `permaura_core::health_proof` byte for byte: a fresh challenge to `/health` with no bearer, answered with lowercase hex HMAC-SHA256 keyed with the token's UTF-8 bytes over `permaura-health-proof:<port>:<challenge>`; only then is the token sent.

export const CHALLENGE_HEADER = "x-permaura-challenge";
export const PROOF_HEADER = "x-permaura-proof";

/** A fresh challenge: 32 random bytes as 64 lowercase hex characters. */
export function newChallenge() {
  return crypto.randomBytes(32).toString("hex");
}

/** The proof a gateway listening on `port` and holding `token` gives for `challenge`, or null. */
export function healthProof(token, port, challenge) {
  if (!token || typeof challenge !== "string" || !/^[A-Za-z0-9_-]{16,64}$/.test(challenge)) return null;
  return crypto
    .createHmac("sha256", Buffer.from(token, "utf8"))
    .update(`permaura-health-proof:${port}:${challenge}`, "utf8")
    .digest("hex");
}

/** Whether `offered` is that proof. Constant-time, exact match only. */
export function verifyHealthProof(token, port, challenge, offered) {
  const expected = healthProof(token, port, challenge);
  if (!expected || typeof offered !== "string") return false;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(offered.trim(), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/** `host:port` (IPv6 hosts in brackets) as the parts `http.request` takes. */
function splitAddr(addr) {
  const i = addr.lastIndexOf(":");
  return { host: addr.slice(0, i).replace(/^\[|\]$/g, ""), port: Number(addr.slice(i + 1)) || 80 };
}

/** One request to `addr`, resolving to the response (body drained) or null on any failure. */
function request(addr, options, timeoutMs) {
  const { host, port } = splitAddr(addr);
  return new Promise((resolve) => {
    // `agent: false`: with NODE_USE_ENV_PROXY set, the global agent sends even 127.0.0.1 through HTTP_PROXY, bearer and all.
    const req = http.request({ host, port, timeout: timeoutMs, agent: false, ...options }, (res) => {
      res.resume();
      resolve(res);
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

/** Whether the listener on `addr` proves it holds `token`, asked with a challenge and nothing else. */
export async function proveListener(addr, token, timeoutMs = 1500) {
  const challenge = newChallenge();
  const res = await request(
    addr,
    { method: "GET", path: "/health", headers: { [CHALLENGE_HEADER]: challenge } },
    timeoutMs,
  );
  const offered = res?.headers?.[PROOF_HEADER];
  return verifyHealthProof(token, splitAddr(addr).port, challenge, typeof offered === "string" ? offered : null);
}

/**
 * Best-effort graceful stop: `POST /v1/shutdown` (operator-authed, loopback-only) asks the gateway to
 * drain in-flight requests and exit on its own. Resolves true on 202, and false on anything else, the
 * caller then signalling its own child instead. The token goes only to a listener that has just proved
 * it already holds it: whatever holds the port may not be the child at all.
 */
export async function shutdownIfProven(addr, token, timeoutMs = 1500) {
  if (!token || !(await proveListener(addr, token, timeoutMs))) return false;
  const res = await request(
    addr,
    { method: "POST", path: "/v1/shutdown", headers: { Authorization: `Bearer ${token}` } },
    timeoutMs,
  );
  return res?.statusCode === 202;
}

/**
 * The graceful stop the launcher runs on Ctrl-C, with the operator token read when the stop happens rather than when the gateway started: the gateway replaces `operator.token` once permaura.com holds a console session, so a token read at start is no longer the one the listener proves, and the stop would always fall back to signalling the child.
 */
export async function stopWithCurrentToken(addr, readToken, timeoutMs = 1500) {
  const token = readToken();
  return token ? shutdownIfProven(addr, token, timeoutMs) : false;
}
