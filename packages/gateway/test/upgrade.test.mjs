import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { binaryFilename, platformKey, releaseTrustRoot, upgradePlan } from "../bin/lib.mjs";

const CLI = fileURLToPath(new URL("../bin/cli.mjs", import.meta.url));
const LAUNCHER = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
const skip = process.platform === "win32" && "the stand-in gateway binary is a shell script";

/** A release channel on loopback: a manifest naming `version`, signed by a throwaway key, and the binary it points at. */
async function channel(version, binary) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const requests = [];
  let manifest = "";
  let sig = "";
  const server = http.createServer((req, res) => {
    requests.push(req.url);
    if (req.url === "/gateway.json") return res.end(manifest);
    if (req.url === "/gateway.json.sig") return res.end(sig);
    if (req.url === "/bin") return res.end(binary);
    res.statusCode = 404;
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const sha256 = crypto.createHash("sha256").update(binary).digest("hex");
  manifest = JSON.stringify({ version, assets: { [platformKey()]: { url: `${base}/bin`, sha256 } } });
  sig = crypto.sign(null, Buffer.from(manifest), privateKey).toString("base64");
  return {
    requests,
    env: { PERMAURA_MANIFEST_URL: `${base}/gateway.json`, PERMAURA_RELEASE_PUBKEY: publicKey.export({ type: "spki", format: "pem" }) },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const stand_in = (version) => `#!/bin/sh\necho "permaura ${version}"\n`;

/** A throwaway PERMAURA_HOME whose installed gateway reports `version`. */
function installed(version) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-upgrade-test-"));
  const bin = path.join(home, "bin", binaryFilename(platformKey()));
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  fs.writeFileSync(bin, stand_in(version), { mode: 0o755 });
  return { home, bin };
}

/** Async rather than spawnSync: the release channel is served from this same process. */
function run(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, PERMAURA_NO_UPGRADE: "", ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("upgrade refuses a validly signed manifest older than the installed gateway", { skip }, async () => {
  const { home, bin } = installed("1.3.35");
  const ch = await channel("1.3.30", stand_in("1.3.30"));
  try {
    const r = await run(["upgrade"], { ...ch.env, PERMAURA_HOME: home });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /names 1\.3\.30, older than the installed 1\.3\.35/);
    assert.equal(fs.readFileSync(bin, "utf8"), stand_in("1.3.35"), "the installed gateway must be untouched");
    assert.ok(!ch.requests.includes("/bin"), "the older binary must not even be downloaded");
  } finally {
    await ch.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("any other command's upgrade check refuses it too, and runs the installed gateway", { skip }, async () => {
  const { home, bin } = installed("1.3.35");
  const ch = await channel("1.3.30", stand_in("1.3.30"));
  try {
    const r = await run(["status"], { ...ch.env, PERMAURA_HOME: home });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /older than the installed 1\.3\.35/);
    assert.match(r.stdout, /permaura 1\.3\.35/, "the installed gateway ran");
    assert.equal(fs.readFileSync(bin, "utf8"), stand_in("1.3.35"));
  } finally {
    await ch.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// The control: the same harness does install, so the refusals above are the launcher's doing.
test("upgrade still installs a newer gateway from the same kind of channel", { skip }, async () => {
  const { home, bin } = installed("99.3.30");
  const ch = await channel("99.3.35", stand_in("99.3.35"));
  try {
    const r = await run(["upgrade"], { ...ch.env, PERMAURA_HOME: home });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Installed gateway 99\.3\.35/);
    assert.equal(fs.readFileSync(bin, "utf8"), stand_in("99.3.35"));
  } finally {
    await ch.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("upgradePlan never goes backwards, and force only reinstalls the same version", () => {
  const plan = (installed, latest, force = false, haveBinary = true) => upgradePlan({ installed, latest, haveBinary, force });
  assert.equal(plan("1.3.35", "1.3.30", true), "older");
  assert.equal(plan("1.3.35", "1.3.30"), "older");
  assert.equal(plan("1.4.0", "1.4.0-rc.1", true), "older");
  assert.equal(plan("1.3.30", "1.3.35"), "install");
  assert.equal(plan("1.3.35", "1.3.35", true), "install");
  assert.equal(plan("1.3.35", "1.3.35"), "current");
  assert.equal(plan(null, "1.3.30", false, false), "install", "nothing installed: anything verified is an improvement");
  assert.equal(plan(null, "1.3.30", false, true), "install", "an unreadable binary is repaired, since there is no version to protect");
});

// npm publishes the launcher over its own channel, so its version is a floor a replayed manifest cannot move.
test("a fresh install refuses a validly signed manifest older than the launcher itself", { skip }, async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-upgrade-test-"));
  const bin = path.join(home, "bin", binaryFilename(platformKey()));
  const ch = await channel("0.0.1", stand_in("0.0.1"));
  try {
    const r = await run(["upgrade"], { ...ch.env, PERMAURA_HOME: home });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, new RegExp(`names 0\\.0\\.1, older than this launcher \\(${LAUNCHER.replace(/\./g, "\\.")}\\)`));
    assert.ok(!fs.existsSync(bin), "nothing may be installed");
    assert.ok(!ch.requests.includes("/bin"), "the older binary must not even be downloaded");
  } finally {
    await ch.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("a fresh install takes a manifest naming the launcher's own version or newer", { skip }, async () => {
  for (const version of [LAUNCHER, "99.0.0"]) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-upgrade-test-"));
    const bin = path.join(home, "bin", binaryFilename(platformKey()));
    const ch = await channel(version, stand_in(version));
    try {
      const r = await run(["upgrade"], { ...ch.env, PERMAURA_HOME: home });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, new RegExp(`Installed gateway ${version.replace(/\./g, "\\.")}`));
      assert.equal(fs.readFileSync(bin, "utf8"), stand_in(version));
    } finally {
      await ch.close();
      fs.rmSync(home, { recursive: true, force: true });
    }
  }
});

test("a manifest below the launcher is not installed over a cached gateway either, which keeps running", { skip }, async () => {
  const { home, bin } = installed("0.0.1");
  const ch = await channel("0.0.2", stand_in("0.0.2"));
  try {
    const r = await run(["status"], { ...ch.env, PERMAURA_HOME: home });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /names 0\.0\.2, older than this launcher/);
    assert.match(r.stdout, /permaura 0\.0\.1/, "the cached gateway ran");
    assert.equal(fs.readFileSync(bin, "utf8"), stand_in("0.0.1"));
    assert.ok(!ch.requests.includes("/bin"));
  } finally {
    await ch.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("upgradePlan refuses a manifest below the floor, installed or not", () => {
  const plan = (installed, latest, floor, haveBinary = installed !== null) => upgradePlan({ installed, latest, haveBinary, floor });
  assert.equal(plan(null, "1.3.40", "1.3.45"), "stale");
  assert.equal(plan(null, "1.3.46-rc.1", "1.3.46"), "stale");
  assert.equal(plan(null, "1.3.45", "1.3.45"), "install");
  assert.equal(plan(null, "1.3.46", "1.3.45"), "install");
  assert.equal(plan("1.3.30", "1.3.40", "1.3.45"), "stale");
  assert.equal(plan("1.3.45", "1.3.40", "1.3.45"), "older");
  assert.equal(plan("1.3.45", "1.3.45", "1.3.45"), "current");
  assert.equal(plan(null, "1.3.40", undefined), "install", "no floor is the previous behavior");
});

test("the release trust root is the environment's only from a source checkout", () => {
  const pinned = ["PINNED"];
  const env = { PERMAURA_MANIFEST_URL: "https://attacker.example/gateway.json", PERMAURA_RELEASE_PUBKEY: "ATTACKER" };
  const shipped = releaseTrustRoot({ env, sourceCheckout: false, pinnedKeys: pinned, manifestUrl: "https://dist/gateway.json" });
  assert.deepEqual(shipped, {
    manifestUrl: "https://dist/gateway.json",
    keys: pinned,
    ignored: ["PERMAURA_MANIFEST_URL", "PERMAURA_RELEASE_PUBKEY"],
  });
  const checkout = releaseTrustRoot({ env, sourceCheckout: true, pinnedKeys: pinned, manifestUrl: "https://dist/gateway.json" });
  assert.deepEqual(checkout, { manifestUrl: env.PERMAURA_MANIFEST_URL, keys: ["ATTACKER"], ignored: [] });
  assert.deepEqual(releaseTrustRoot({ env: {}, sourceCheckout: false, pinnedKeys: pinned, manifestUrl: "u" }).ignored, []);
});

test("a published launcher (bin/ alone) says it ignores both overrides", async () => {
  const pkg = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-published-"));
  try {
    fs.mkdirSync(path.join(pkg, "bin"));
    for (const f of ["cli.mjs", "lib.mjs"]) fs.copyFileSync(new URL(`../bin/${f}`, import.meta.url), path.join(pkg, "bin", f));
    fs.copyFileSync(new URL("../package.json", import.meta.url), path.join(pkg, "package.json"));
    const env = { PERMAURA_MANIFEST_URL: "http://127.0.0.1:9/gateway.json", PERMAURA_RELEASE_PUBKEY: "ATTACKER" };
    const r = await new Promise((resolve) => {
      const child = spawn(process.execPath, [path.join(pkg, "bin", "cli.mjs"), "--version"], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (d) => (stderr += d));
      child.on("close", (status) => resolve({ status, stderr }));
    });
    assert.match(r.stderr, /PERMAURA_MANIFEST_URL is set and ignored/);
    assert.match(r.stderr, /PERMAURA_RELEASE_PUBKEY is set and ignored/);
    const checkout = await run(["--version"], env);
    assert.doesNotMatch(checkout.stderr, /ignored/, "a source checkout still honors them, which is how these tests run");
  } finally {
    fs.rmSync(pkg, { recursive: true, force: true });
  }
});
