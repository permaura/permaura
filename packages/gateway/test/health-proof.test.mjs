import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

import {
  CHALLENGE_HEADER,
  PROOF_HEADER,
  healthProof,
  newChallenge,
  proveListener,
  shutdownIfProven,
  stopWithCurrentToken,
  verifyHealthProof,
} from "../bin/lib.mjs";

const TOKEN = "pgt_ag01testvectortoken";
const CHALLENGE = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

// The vectors `permaura_core::health_proof` is held to, so the launcher and the gateway agree on the bytes.
test("the proof matches the Rust helper's fixed vectors", () => {
  assert.equal(healthProof(TOKEN, 7376, CHALLENGE), "4900eebce3ab46dfd1a9fa5d468d6f7021db4d73e4b37ba51fc75db2e223f767");
  assert.equal(healthProof(TOKEN, 7399, CHALLENGE), "2113557bb0c5c1811fd553ba0180fcc7b0314b92055601779cbab61edd661deb");
  assert.equal(healthProof(TOKEN, 7376, "AbCdEf_-0123456789"), "a09bf5e8d626c26a083efef3b9354a784fb034b1d56a230a05d9a3587caa1845");
});

test("only the matching proof verifies", () => {
  const p = healthProof(TOKEN, 7376, CHALLENGE);
  assert.ok(verifyHealthProof(TOKEN, 7376, CHALLENGE, p));
  assert.ok(!verifyHealthProof("pgt_someoneelse", 7376, CHALLENGE, p), "another token");
  assert.ok(!verifyHealthProof(TOKEN, 7399, CHALLENGE, p), "relayed from another port");
  assert.ok(!verifyHealthProof(TOKEN, 7376, newChallenge(), p), "another challenge");
  assert.ok(!verifyHealthProof(TOKEN, 7376, CHALLENGE, p.toUpperCase()), "exact match only");
  assert.ok(!verifyHealthProof(TOKEN, 7376, CHALLENGE, p.slice(0, 63)), "truncated");
  assert.ok(!verifyHealthProof(TOKEN, 7376, CHALLENGE, null), "no proof");
  assert.ok(!verifyHealthProof("", 7376, CHALLENGE, p), "no token");
  assert.equal(healthProof(TOKEN, 7376, "short"), null);
  assert.equal(healthProof(TOKEN, 7376, "0123456789abcdef+/=="), null);
  assert.equal(newChallenge().length, 64);
});

/**
 * A loopback listener that answers `/health` like a gateway, with the proof `answer` says, accepts
 * `POST /v1/shutdown` with 202, and records every request's method, path and headers.
 */
async function fakeGateway(answer) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, path: req.url, headers: req.headers });
    const port = server.address().port;
    if (req.method === "GET" && req.url === "/health") {
      const challenge = req.headers[CHALLENGE_HEADER];
      const proof =
        answer === "right" ? healthProof(TOKEN, port, challenge)
        : answer === "wrong" ? healthProof("pgt_some_other_store", port, challenge)
        : null;
      const headers = { "content-type": "application/json" };
      if (proof) headers[PROOF_HEADER] = proof;
      res.writeHead(200, headers);
      res.end(JSON.stringify({ status: "ok", service: "permaura-gateway" }));
      return;
    }
    res.writeHead(req.method === "POST" && req.url === "/v1/shutdown" ? 202 : 404);
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { addr: `127.0.0.1:${server.address().port}`, seen, close: () => new Promise((r) => server.close(r)) };
}

// A listener holding the port that answers like a gateway but cannot prove it holds the
// operator token is sent a challenge and nothing else, and the launcher falls back to its own child.
for (const answer of ["none", "wrong"]) {
  test(`a listener with ${answer === "none" ? "no" : "a wrong"} proof is never sent the bearer`, async () => {
    const gw = await fakeGateway(answer);
    try {
      assert.equal(await proveListener(gw.addr, TOKEN), false);
      assert.equal(await shutdownIfProven(gw.addr, TOKEN), false, "the caller signals its own child instead");
      assert.ok(gw.seen.length > 0);
      for (const r of gw.seen) {
        assert.equal(r.method, "GET", JSON.stringify(r));
        assert.equal(r.path, "/health");
        assert.equal(r.headers.authorization, undefined, "no bearer of any kind");
        assert.ok(!JSON.stringify(r.headers).includes(TOKEN), "the token went to the holder");
        assert.match(r.headers[CHALLENGE_HEADER], /^[0-9a-f]{64}$/);
      }
    } finally {
      await gw.close();
    }
  });
}

test("a listener with the right proof is sent the bearer, after the challenge", async () => {
  const gw = await fakeGateway("right");
  try {
    assert.equal(await shutdownIfProven(gw.addr, TOKEN), true);
    assert.deepEqual(gw.seen.map((r) => `${r.method} ${r.path}`), ["GET /health", "POST /v1/shutdown"]);
    assert.equal(gw.seen[0].headers.authorization, undefined, "the challenge carries no bearer");
    assert.equal(gw.seen[1].headers.authorization, `Bearer ${TOKEN}`);
  } finally {
    await gw.close();
  }
});

test("nothing listening proves nothing and sends nothing", async () => {
  const gw = await fakeGateway("right");
  const { addr } = gw;
  await gw.close();
  assert.equal(await shutdownIfProven(addr, TOKEN), false);
});

// With NODE_USE_ENV_PROXY set, Node routes the global agent through HTTP_PROXY, 127.0.0.1 included (seen on 22.22 and 26), so a proxy that relays the challenge is then handed the bearer. Node 20 ignores the variable, so there this passes either way.
test("a proxy named in the environment is never handed the bearer", async () => {
  const gw = await fakeGateway("right");
  const proxied = [];
  const proxy = net.createServer((socket) => {
    socket.once("data", (d) => {
      proxied.push(d.toString("utf8"));
      socket.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
    });
  });
  await new Promise((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
  try {
    const lib = new URL("../bin/lib.mjs", import.meta.url).href;
    const script = `const { shutdownIfProven } = await import(${JSON.stringify(lib)}); process.stdout.write(String(await shutdownIfProven(${JSON.stringify(gw.addr)}, ${JSON.stringify(TOKEN)})));`;
    const env = { ...process.env, NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxyUrl, http_proxy: proxyUrl };
    delete env.NO_PROXY;
    delete env.no_proxy;
    const out = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script], { env });
      let stdout = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.on("error", reject);
      child.on("close", () => resolve(stdout.trim()));
    });
    assert.equal(proxied.length, 0, `the proxy was sent: ${proxied.map((r) => r.split("\r\n")[0]).join(", ")}`);
    assert.equal(out, "true");
    assert.deepEqual(gw.seen.map((r) => `${r.method} ${r.path}`), ["GET /health", "POST /v1/shutdown"]);
  } finally {
    await new Promise((r) => proxy.close(r));
    await gw.close();
  }
});

// The gateway replaces operator.token once permaura.com holds a console session, so the launcher's Ctrl-C stop reads the file when it stops: the token it read at start no longer proves the listener and would fall back to signalling the child.
test("the graceful stop presents the token the file names when it stops, not the one read at start", async () => {
  const gw = await fakeGateway("right");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "permaura-stop-"));
  const file = path.join(dir, "operator.token");
  try {
    fs.writeFileSync(file, "pgt_read_when_the_gateway_started\n");
    const atStart = fs.readFileSync(file, "utf8").trim();
    fs.writeFileSync(file, `${TOKEN}\n`);
    assert.equal(await shutdownIfProven(gw.addr, atStart), false, "the token cached at start no longer proves the listener");
    const read = () => fs.readFileSync(file, "utf8").trim() || null;
    assert.equal(await stopWithCurrentToken(gw.addr, read), true);
    const shutdown = gw.seen.filter((r) => r.method === "POST" && r.path === "/v1/shutdown");
    assert.equal(shutdown.length, 1, JSON.stringify(gw.seen));
    assert.equal(shutdown[0].headers.authorization, `Bearer ${TOKEN}`);
    assert.ok(!gw.seen.some((r) => JSON.stringify(r.headers).includes(atStart)), "the old token is never sent");

    const before = gw.seen.length;
    assert.equal(await stopWithCurrentToken(gw.addr, () => null), false, "no token, no request");
    assert.equal(gw.seen.length, before);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    await gw.close();
  }
});
