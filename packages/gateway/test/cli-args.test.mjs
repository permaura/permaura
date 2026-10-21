import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// fileURLToPath, never `.pathname`: on Windows the latter yields "/D:/a/..." and node then resolves
// it against the drive as "D:\\D:\\a\\...". These tests are spawn-based, so that failure only ever
// shows up on a win32 runner.
const CLI = fileURLToPath(new URL("../bin/cli.mjs", import.meta.url));

/** Run the launcher with a throwaway PERMAURA_HOME so nothing touches the real one. */
function run(args) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-cli-test-"));
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, PERMAURA_HOME: home, PERMAURA_NO_UPGRADE: "1" },
    timeout: 20_000,
  });
  // A run that got as far as fetching a binary would have created bin/. The point of these tests is
  // that argument handling costs nothing, so report it.
  const fetched = fs.existsSync(path.join(home, "bin"));
  fs.rmSync(home, { recursive: true, force: true });
  return { ...r, fetched };
}

test("--help prints usage and exits 0 without starting anything", () => {
  const r = run(["--help"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Usage:/);
  assert.match(r.stdout, /permaura start/);
  assert.equal(r.fetched, false, "help must not download a binary");
});

// The headline of the unified binary: `permaura` alone is someone asking what it does, not an
// instruction to bind a port and serve until killed.
test("no arguments prints help and starts nothing", () => {
  const r = run([]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /Usage:/);
  assert.equal(r.fetched, false, "a bare invocation must not download a binary");
  assert.doesNotMatch(r.stdout, /Starting gateway/, "a bare invocation must not start a gateway");
});

test("-h is the same as --help", () => {
  assert.equal(run(["-h"]).status, 0);
});

// The whole point of the item: this used to boot a long-running gateway and bind a port.
test("an unknown flag exits non-zero without starting a server", () => {
  const r = run(["--nope"]);
  assert.notEqual(r.status, 0, "an unknown flag must not succeed");
  assert.match(r.stderr, /unknown argument/);
  assert.match(r.stderr, /Usage:/, "the error must show how to use it");
  assert.equal(r.fetched, false, "a typo must not download a binary");
});

test("a mistyped subcommand is an error, not an instruction to run", () => {
  const r = run(["upgrde"]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /unknown command/);
  assert.equal(r.fetched, false, "a typo must not download a binary");
});

// `--url`/`--token` take a value, and that value must never be mistaken for the subcommand,
// otherwise `--token start` would boot a gateway.
test("a global flag's value is not read as the command", () => {
  const r = run(["--token", "start"]);
  assert.notEqual(r.status, 0, "there is no command here, only a flag and its value");
  assert.match(r.stderr, /unknown argument/);
  assert.equal(r.fetched, false);
});

test("--version still works and is not treated as unknown", () => {
  const r = run(["--version"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /permaura \(launcher\)/);
  assert.match(r.stdout, /permaura \(binary\)/);
});
