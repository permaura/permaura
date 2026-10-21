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
const skip = process.platform === "win32" && "the stand-in gateway binary is a script run through its shebang";
const TOKEN = "pgt_start_addr_fixture_token";

// The stand-in gateway. `start` binds with clap's precedence (`--addr`, either form, over PERMAURA_ADDR), answers the health-proof challenge with the real proof, and drains on an authorised POST /v1/shutdown; every request and signal lands in events.jsonl.
const standIn = (libUrl) => `#!${process.execPath}
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const args = process.argv.slice(2);
if (args.includes("--version")) { console.log("permaura 1.0.0"); process.exit(0); }
if (args[0] !== "start") { console.log("stand-in forwarded " + JSON.stringify(args)); process.exit(0); }
const home = process.env.PERMAURA_HOME;
const event = (e) => fs.appendFileSync(path.join(home, "events.jsonl"), JSON.stringify(e) + "\\n");
const at = args.indexOf("--addr");
const eq = args.find((a) => a.startsWith("--addr="));
const addr = at >= 0 ? args[at + 1] : eq ? eq.slice(7) : process.env.PERMAURA_ADDR;
const token = fs.readFileSync(path.join(home, "operator.token"), "utf8").trim();
const i = addr.lastIndexOf(":");
const port = Number(addr.slice(i + 1));
import(${JSON.stringify(libUrl)}).then(({ healthProof, CHALLENGE_HEADER, PROOF_HEADER }) => {
  const server = http.createServer((req, res) => {
    const auth = req.headers.authorization === "Bearer " + token;
    event({ method: req.method, path: req.url, auth, challenged: Boolean(req.headers[CHALLENGE_HEADER]) });
    if (req.method === "GET" && req.url === "/health") {
      const proof = healthProof(token, port, req.headers[CHALLENGE_HEADER]);
      res.writeHead(200, proof ? { [PROOF_HEADER]: proof } : {});
      return res.end(JSON.stringify({ service: "permaura-gateway", status: "ok" }));
    }
    if (req.method === "POST" && req.url === "/v1/shutdown" && auth) {
      res.writeHead(202);
      return res.end(() => process.exit(0));
    }
    res.writeHead(404);
    res.end();
  });
  server.listen(port, addr.slice(0, i).replace(/^\\[|\\]$/g, ""), () => event({ listening: addr }));
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => { event({ signal }); process.exit(0); });
`;

const listen = (server) =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`127.0.0.1:${server.address().port}`)));
const close = (server) => new Promise((resolve) => server.close(resolve));

async function freeAddr() {
  const server = http.createServer();
  const addr = await listen(server);
  await close(server);
  return addr;
}

/** A throwaway PERMAURA_HOME holding the stand-in and its operator token, with the release channel pointed at a closed port so the cached stand-in is what runs. */
async function home() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-start-addr-test-"));
  const bin = path.join(dir, "bin", lib.binaryFilename(lib.platformKey()));
  fs.mkdirSync(path.dirname(bin), { recursive: true });
  fs.writeFileSync(bin, standIn(new URL("../bin/lib.mjs", import.meta.url).href), { mode: 0o755 });
  fs.writeFileSync(path.join(dir, "operator.token"), `${TOKEN}\n`, { mode: 0o600 });
  return {
    dir,
    env: {
      ...process.env,
      PERMAURA_HOME: dir,
      PERMAURA_TOKEN: "",
      PERMAURA_NO_UPGRADE: "1",
      PERMAURA_MANIFEST_URL: `http://${await freeAddr()}/gateway.json`,
    },
    events: () => {
      const file = path.join(dir, "events.jsonl");
      return fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l)) : [];
    },
    remove: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** Run `permaura start …` and Ctrl-C the launcher alone once it reports the gateway running, so only the launcher's own shutdown path can stop the stand-in. */
function start(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let interrupted = false;
    const timer = setTimeout(() => child.kill("SIGKILL"), 40_000);
    child.stdout.on("data", (d) => {
      stdout += d;
      if (!interrupted && stdout.includes("Press Ctrl-C to stop")) {
        interrupted = true;
        // The line can reach this pipe before the launcher's next statement installs its SIGINT handler, and Node's default for an unhandled SIGINT is to die.
        setTimeout(() => child.kill("SIGINT"), 200);
      }
    });
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

/** Everything a supervised start has to get right about the address its child is actually on. */
function assertSupervised(r, events, addr) {
  assert.equal(r.status, 0, `the launcher must keep and then cleanly stop a healthy gateway\n${r.stdout}\n${r.stderr}`);
  assert.deepEqual(events.find((e) => e.listening), { listening: addr });
  assert.ok(events.some((e) => e.method === "GET" && e.path === "/health" && !e.challenged), "health was polled on the child's address");
  assert.match(r.stdout, new RegExp(`Gateway running at http://${addr}\\b`));
  assert.match(r.stdout, new RegExp(`PERMAURA_PAIR_CODE=<code> permaura pair --url http://${addr}\\b`), "the pairing instruction names the child's address, with the code in the environment");
  assert.ok(!r.stdout.includes(TOKEN) && !r.stderr.includes(TOKEN), "the operator token is never printed");
  assert.doesNotMatch(r.stdout, /Settings → Gateways/, "no pointer to the console form that no longer exists");
  const shutdown = events.filter((e) => e.path === "/v1/shutdown");
  assert.deepEqual(shutdown, [{ method: "POST", path: "/v1/shutdown", auth: true, challenged: false }], "graceful shutdown reached the child");
  const proved = events.findIndex((e) => e.challenged);
  assert.ok(proved >= 0 && proved < events.findIndex((e) => e.path === "/v1/shutdown"), "the bearer followed a proved challenge");
  assert.ok(!events.some((e) => e.signal), "the child was drained over HTTP, not signalled");
}

for (const form of ["--addr <addr>", "--addr=<addr>"]) {
  test(`start ${form} supervises the flag's address, not PERMAURA_ADDR`, { skip, timeout: 60_000 }, async () => {
    const h = await home();
    const stale = [];
    const wrong = http.createServer((req, res) => {
      stale.push({ method: req.method, path: req.url, headers: req.headers });
      res.writeHead(503);
      res.end("not the gateway");
    });
    const wrongAddr = await listen(wrong);
    try {
      const addr = await freeAddr();
      const flag = form === "--addr <addr>" ? ["--addr", addr] : [`--addr=${addr}`];
      const r = await start(["start", ...flag], { ...h.env, PERMAURA_ADDR: wrongAddr });
      assertSupervised(r, h.events(), addr);
      assert.match(r.stdout, new RegExp(`Starting gateway at http://${addr}\\b`));
      assert.equal(stale.length, 0, `the overridden address was contacted: ${JSON.stringify(stale.map((s) => `${s.method} ${s.path}`))}`);
      assert.ok(!r.stdout.includes(wrongAddr) && !r.stderr.includes(wrongAddr), "the overridden address is never shown");
    } finally {
      await close(wrong);
      h.remove();
    }
  });
}

test("PERMAURA_ADDR alone still picks the address", { skip, timeout: 60_000 }, async () => {
  const h = await home();
  try {
    const addr = await freeAddr();
    const r = await start(["start"], { ...h.env, PERMAURA_ADDR: addr });
    assertSupervised(r, h.events(), addr);
  } finally {
    h.remove();
  }
});

test("startAddr follows the binary's precedence: --addr, then PERMAURA_ADDR, then the default", () => {
  const env = { PERMAURA_ADDR: "127.0.0.1:7400" };
  assert.equal(lib.startAddr([], {}), "127.0.0.1:7376");
  assert.equal(lib.startAddr([], { PERMAURA_ADDR: "" }), "127.0.0.1:7376", "an empty variable is unset, as the launcher passes the default on");
  assert.equal(lib.startAddr([], env), "127.0.0.1:7400");
  assert.equal(lib.startAddr(["--addr", "127.0.0.1:7401"], env), "127.0.0.1:7401");
  assert.equal(lib.startAddr(["--addr=127.0.0.1:7402"], env), "127.0.0.1:7402");
  assert.equal(lib.startAddr(["--pair", "PGW-1", "--mock", "--addr", "[::1]:7403"], env), "[::1]:7403");
  assert.equal(lib.startAddr(["--", "--addr", "127.0.0.1:7404"], env), "127.0.0.1:7400", "nothing after `--` is a flag");
  assert.equal(lib.startAddr(["--addr"], env), "127.0.0.1:7400", "a flag with no value is clap's error to report, not an address");
});

test("reachableAddr points an all-interfaces bind at loopback and leaves the rest alone", () => {
  assert.equal(lib.reachableAddr("0.0.0.0:7376"), "127.0.0.1:7376");
  assert.equal(lib.reachableAddr("[::]:7377"), "[::1]:7377");
  assert.equal(lib.reachableAddr("[0:0:0:0:0:0:0:0]:7378"), "[::1]:7378");
  assert.equal(lib.reachableAddr("127.0.0.1:7379"), "127.0.0.1:7379");
  assert.equal(lib.reachableAddr("[::1]:7380"), "[::1]:7380");
  assert.equal(lib.reachableAddr("192.0.2.10:7381"), "192.0.2.10:7381");
});
