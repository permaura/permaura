import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as lib from "../bin/lib.mjs";

const CLI = fileURLToPath(new URL("../bin/cli.mjs", import.meta.url));
const MOD_RS = fileURLToPath(new URL("../../../services/gateway/src/cli/mod.rs", import.meta.url));
const skip = process.platform === "win32" && "the stand-in gateway binary is a script run through its shebang";

/** The top-level subcommands clap derives from `enum Command` in the binary's cli/mod.rs, kebab-cased as clap names them. */
function binaryCommands() {
  const src = fs.readFileSync(MOD_RS, "utf8");
  const body = /\benum Command \{([\s\S]*?)\r?\n\}/.exec(src)?.[1];
  assert.ok(body, `no \`enum Command\` in ${MOD_RS}`);
  // A rename or alias changes what the user types without changing the variant, so this reader would silently disagree with clap.
  assert.doesNotMatch(body, /#\[command\([^\]]*\b(name|alias|aliases|visible_alias)\b/, "teach binaryCommands() the new attribute");
  const names = [...body.matchAll(/^ {4}([A-Z][A-Za-z0-9]*)\b/gm)].map((m) => m[1].replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase());
  assert.ok(names.includes("start") && names.length > 10, `implausible command list: ${names}`);
  return names;
}

// Every invocation, `--version` included, is logged, so a test can tell that the binary never ran at all.
const standIn = `#!${process.execPath}
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
fs.appendFileSync(path.join(process.env.PERMAURA_HOME, "invocations.jsonl"), JSON.stringify(args) + "\\n");
if (args.includes("--version")) { console.log("permaura 1.0.0"); process.exit(0); }
console.log("stand-in forwarded " + JSON.stringify(args));
`;

async function home() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-command-parity-test-"));
  const bin = path.join(dir, "bin", lib.binaryFilename(lib.platformKey()));
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  fs.writeFileSync(bin, standIn, { mode: 0o755 });
  // A closed port for the release channel, so the cached stand-in is what runs and nothing leaves the machine.
  const server = http.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const channel = `http://127.0.0.1:${server.address().port}/gateway.json`;
  await new Promise((resolve) => server.close(resolve));
  const log = path.join(dir, "invocations.jsonl");
  return {
    env: { ...process.env, PERMAURA_HOME: dir, PERMAURA_NO_UPGRADE: "1", PERMAURA_MANIFEST_URL: channel },
    invocations: () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : []),
    remove: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

function run(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("the launcher's command list is the binary's, plus clap's own help", () => {
  assert.ok(Array.isArray(lib.COMMANDS), "lib.mjs exports COMMANDS");
  assert.deepEqual([...lib.COMMANDS].sort(), [...binaryCommands(), "help"].sort());
});

// `start` and `upgrade` are the launcher's own halves; everything else must reach the binary untouched. `--help` keeps every one of them, uninstall included, a read-only call on the real binary.
test("every other binary command is forwarded unchanged", { skip, timeout: 60_000 }, async () => {
  const h = await home();
  try {
    const commands = binaryCommands().filter((c) => c !== "start" && c !== "upgrade");
    const results = await Promise.all(commands.map(async (command) => ({ command, ...(await run([command, "--help"], h.env)) })));
    const refused = results
      .filter((r) => r.status !== 0 || !r.stdout.includes(`stand-in forwarded ${JSON.stringify([r.command, "--help"])}`))
      .map((r) => ({ command: r.command, status: r.status, unknown: r.stderr.includes("unknown command") }));
    assert.deepEqual(refused, [], "a command the binary supports must reach it");
  } finally {
    h.remove();
  }
});

test("a command the binary does not have is still refused before anything runs", { skip, timeout: 30_000 }, async () => {
  const h = await home();
  try {
    for (const args of [["frobnicate"], ["pairs", "PGW-XXXX"], ["Pair", "--help"]]) {
      const r = await run(args, h.env);
      assert.equal(r.status, 2, `${args[0]}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, new RegExp(`unknown command: ${args[0]}`));
      assert.doesNotMatch(r.stdout, /Couldn't check for updates/, "a typo must not even reach the release channel");
    }
    assert.deepEqual(h.invocations(), [], "the binary must not run for a command it does not have");
  } finally {
    h.remove();
  }
});

test("control: status still reaches the binary with its arguments unchanged", { skip, timeout: 30_000 }, async () => {
  const h = await home();
  try {
    const r = await run(["--url", "http://127.0.0.1:7399", "status"], h.env);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /stand-in forwarded \["--url","http:\/\/127\.0\.0\.1:7399","status"\]/);
  } finally {
    h.remove();
  }
});
