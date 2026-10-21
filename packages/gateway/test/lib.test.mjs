import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

import {
  platformKey,
  binaryFilename,
  assetName,
  compareVersions,
  sweepOldBinaries,
  swapBinaryIntoPlace,
  verifyDetachedSignature,
  verifyDetachedSignatureAny,
} from "../bin/lib.mjs";

function tmpBinDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "permaura-lib-test-"));
}

test("platformKey covers the 6-target matrix and rejects the rest", () => {
  const table = [
    // [platform, arch, expected]
    ["darwin", "arm64", "darwin-arm64"],
    ["darwin", "x64", "darwin-amd64"],
    ["linux", "x64", "linux-amd64"],
    ["linux", "arm64", "linux-arm64"],
    ["win32", "x64", "win32-amd64"],
    ["win32", "arm64", "win32-arm64"],
    // unsupported
    ["freebsd", "x64", null],
    ["sunos", "arm64", null],
    ["darwin", "ia32", null],
    ["win32", "ia32", null],
    ["linux", "riscv64", null],
    ["aix", "ppc64", null],
  ];
  for (const [platform, arch, expected] of table) {
    assert.equal(platformKey(platform, arch), expected, `${platform}/${arch}`);
  }
});

test("platformKey defaults to the current process", () => {
  assert.equal(platformKey(), platformKey(process.platform, process.arch));
});

test("binaryFilename adds .exe only for win32 keys", () => {
  assert.equal(binaryFilename("darwin-arm64"), "permaura");
  assert.equal(binaryFilename("darwin-amd64"), "permaura");
  assert.equal(binaryFilename("linux-amd64"), "permaura");
  assert.equal(binaryFilename("linux-arm64"), "permaura");
  assert.equal(binaryFilename("win32-amd64"), "permaura.exe");
  assert.equal(binaryFilename("win32-arm64"), "permaura.exe");
  // A null key (unsupported platform) still yields a sane default so path joins never throw.
  assert.equal(binaryFilename(null), "permaura");
});

test("assetName matches the release staging convention", () => {
  assert.equal(assetName("darwin-arm64"), "permaura-darwin-arm64");
  assert.equal(assetName("linux-arm64"), "permaura-linux-arm64");
  assert.equal(assetName("win32-amd64"), "permaura-win32-amd64.exe");
  assert.equal(assetName("win32-arm64"), "permaura-win32-arm64.exe");
});

test("swapBinaryIntoPlace parks the old binary and installs the new one", () => {
  const dir = tmpBinDir();
  const bin = path.join(dir, "permaura");
  const tmp = path.join(dir, "permaura.download");
  fs.writeFileSync(bin, "v1");
  fs.writeFileSync(tmp, "v2");
  swapBinaryIntoPlace(bin, tmp);
  assert.equal(fs.readFileSync(bin, "utf8"), "v2");
  assert.equal(fs.readFileSync(`${bin}.old`, "utf8"), "v1");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("swapBinaryIntoPlace restores the parked binary when the final rename fails", () => {
  const dir = tmpBinDir();
  const bin = path.join(dir, "permaura");
  const tmp = path.join(dir, "permaura.download");
  fs.writeFileSync(bin, "v1");
  fs.writeFileSync(tmp, "v2");
  // Injected fs: the tmp→BIN rename throws (a Windows AV lock on the fresh download, say);
  // everything else is the real fs.
  const failingFs = {
    ...fs,
    renameSync(from, to) {
      if (from === tmp) throw new Error("EBUSY: locked");
      return fs.renameSync(from, to);
    },
  };
  assert.throws(() => swapBinaryIntoPlace(bin, tmp, failingFs), /EBUSY/);
  // The old binary must be back at BIN, never a dead install.
  assert.equal(fs.readFileSync(bin, "utf8"), "v1");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("sweepOldBinaries collects parked files but never the live binary or the in-flight download", () => {
  const dir = tmpBinDir();
  const bin = path.join(dir, "permaura");
  fs.writeFileSync(bin, "live");
  fs.writeFileSync(`${bin}.old`, "parked");
  fs.writeFileSync(`${bin}.old-1234`, "parked-unique");
  fs.writeFileSync(`${bin}.download`, "in-flight");
  sweepOldBinaries(bin);
  assert.ok(fs.existsSync(bin), "live binary survives");
  assert.ok(fs.existsSync(`${bin}.download`), "in-flight download survives");
  assert.ok(!fs.existsSync(`${bin}.old`), ".old swept");
  assert.ok(!fs.existsSync(`${bin}.old-1234`), "unique park swept");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("sweepOldBinaries is a no-op when no live binary exists (a lone .old is the only working copy)", () => {
  const dir = tmpBinDir();
  const bin = path.join(dir, "permaura");
  fs.writeFileSync(`${bin}.old`, "only-copy");
  sweepOldBinaries(bin);
  assert.ok(fs.existsSync(`${bin}.old`), "sole surviving copy must not be swept");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("compareVersions orders dotted versions", () => {
  assert.ok(compareVersions("0.1.0", "0.1.1") < 0);
  assert.ok(compareVersions("0.1.1", "0.1.0") > 0);
  assert.equal(compareVersions("0.1.0", "0.1.0"), 0);
  assert.ok(compareVersions("0.2.0", "0.10.0") < 0);
  assert.ok(compareVersions("1.0.0", "0.9.9") > 0);
  assert.equal(compareVersions("v0.1.0", "0.1.0"), 0);
  assert.ok(compareVersions(null, "0.0.1") < 0);
  assert.ok(compareVersions("0.1", "0.1.0.1") < 0);
});

test("compareVersions ranks a pre-release below its own release", () => {
  // The bug this exists for: the suffix used to be discarded, so a hand-built 1.2.5-dev.1 compared
  // equal to the released 1.2.5 and `upgrade` was never offered.
  assert.ok(compareVersions("1.2.5-dev.1", "1.2.5") < 0);
  assert.ok(compareVersions("1.2.5", "1.2.5-dev.1") > 0);
  assert.equal(compareVersions("1.2.5-dev.1", "1.2.5-dev.1"), 0);
  // A pre-release is still only about its OWN release: it does not outrank a higher one.
  assert.ok(compareVersions("1.2.5-dev.1", "1.2.6") < 0);
  assert.ok(compareVersions("1.2.6-dev.1", "1.2.5") > 0);
});

test("compareVersions orders pre-release identifiers by semver precedence", () => {
  assert.ok(compareVersions("1.0.0-dev.1", "1.0.0-dev.2") < 0);
  assert.ok(compareVersions("1.0.0-dev.2", "1.0.0-dev.10") < 0, "numeric identifiers compare as numbers");
  assert.ok(compareVersions("1.0.0-alpha", "1.0.0-beta") < 0);
  assert.ok(compareVersions("1.0.0-rc", "1.0.0-rc.1") < 0, "a prefix run of identifiers is the older one");
  assert.ok(compareVersions("1.0.0-1", "1.0.0-alpha") < 0, "numeric ranks below alphanumeric");
});

// ── release-manifest signatures ──────────────────────────────────────────────
// Real Ed25519 keys, real signatures: this is the code path that will decide whether a stranger's
// binary runs on a user's machine, so nothing here is mocked.

function keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    pem: publicKey.export({ type: "spki", format: "pem" }),
    sign: (bytes) => crypto.sign(null, Buffer.from(bytes), privateKey).toString("base64"),
    privateKey,
  };
}

test("a manifest signed by the pinned key verifies", () => {
  const k = keypair();
  const manifest = JSON.stringify({ version: "0.2.0", assets: {} });
  assert.equal(verifyDetachedSignature(manifest, k.sign(manifest), k.pem), true);
});

test("a manifest signed by a DIFFERENT key is refused (the whole point)", () => {
  const real = keypair();
  const attacker = keypair();
  const manifest = JSON.stringify({ version: "0.2.0", assets: {} });
  // The attacker signs their own manifest perfectly well; it just isn't OUR key.
  assert.throws(
    () => verifyDetachedSignature(manifest, attacker.sign(manifest), real.pem),
    /did not verify against the pinned/,
  );
});

test("a tampered manifest is refused even with a valid signature over the original", () => {
  const k = keypair();
  const original = JSON.stringify({ version: "0.2.0", assets: { "darwin-arm64": { url: "https://good" } } });
  const sig = k.sign(original);
  const tampered = original.replace("https://good", "https://evil");
  assert.throws(() => verifyDetachedSignature(tampered, sig, k.pem), /did not verify/);
});

test("a malformed signature is rejected as malformed, not merely invalid", () => {
  const k = keypair();
  const manifest = "{}";
  assert.throws(() => verifyDetachedSignature(manifest, "aGk=", k.pem), /malformed \(expected 64 bytes/);
  assert.throws(() => verifyDetachedSignature(manifest, "", k.pem), /malformed \(expected 64 bytes/);
});

test("a non-ed25519 pinned key is refused rather than silently changing algorithm", () => {
  const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = publicKey.export({ type: "spki", format: "pem" });
  assert.throws(() => verifyDetachedSignature("{}", "x".repeat(88), pem), /must be ed25519/);
});

test("a garbage pinned key is refused with a clear message", () => {
  assert.throws(() => verifyDetachedSignature("{}", "x", "not-a-key"), /not a valid public key/);
});

test("signature covers the exact bytes: trailing whitespace is a different document", () => {
  // Guards the detached-over-raw-bytes contract: no canonicalisation, no leniency.
  const k = keypair();
  const manifest = JSON.stringify({ version: "0.2.0" });
  const sig = k.sign(manifest);
  assert.throws(() => verifyDetachedSignature(manifest + "\n", sig, k.pem), /did not verify/);
});

// ---- accepting more than one release key (rotation overlap) -----------------

test("a signature verifies against any key in the accepted set, whichever position it holds", () => {
  const a = keypair();
  const b = keypair();
  const manifest = '{"version":"9.9.9"}';
  // Signed by the SECOND key: rotation's whole point is that a manifest signed by the incoming key
  // verifies on a client that still lists the outgoing one first.
  assert.equal(verifyDetachedSignatureAny(manifest, b.sign(manifest), [a.pem, b.pem]), true);
  assert.equal(verifyDetachedSignatureAny(manifest, a.sign(manifest), [a.pem, b.pem]), true);
});

test("a key outside the accepted set is still refused, however many keys are listed", () => {
  const a = keypair();
  const b = keypair();
  const attacker = keypair();
  const manifest = '{"version":"9.9.9"}';
  assert.throws(
    () => verifyDetachedSignatureAny(manifest, attacker.sign(manifest), [a.pem, b.pem]),
    /did not verify against any of the 2/,
  );
});

test("a malformed pin fails loudly rather than silently shrinking the accepted set", () => {
  const a = keypair();
  const manifest = '{"version":"9.9.9"}';
  // A typo in the second pin must not leave a build quietly accepting one key while its source
  // claims two. Every key is parsed before any is tried.
  assert.throws(
    () => verifyDetachedSignatureAny(manifest, a.sign(manifest), [a.pem, "not-a-key"]),
    /not a valid public key/,
  );
});

test("an empty accepted set verifies nothing rather than everything", () => {
  const a = keypair();
  const manifest = '{"version":"9.9.9"}';
  assert.throws(() => verifyDetachedSignatureAny(manifest, a.sign(manifest), []), /no release key is pinned/);
  assert.throws(() => verifyDetachedSignatureAny(manifest, a.sign(manifest), [""]), /no release key is pinned/);
});

test("a malformed signature is reported as malformed, not as a key mismatch", () => {
  const a = keypair();
  const b = keypair();
  // Checked once, before any key is tried: a wrong length is malformed whichever key you hold, and
  // "no key matched" would send the reader hunting for a key problem they do not have.
  assert.throws(
    () => verifyDetachedSignatureAny('{"v":1}', "aGk=", [a.pem, b.pem]),
    /malformed \(expected 64 bytes/,
  );
});
