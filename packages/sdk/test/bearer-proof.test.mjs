import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHash, createHmac } from "node:crypto";

import { PermauraClient, PermauraApiError, bearerDigest, bearerKey, bearerProof } from "../dist/index.js";

const TOKEN = "tok_sdk_bearer_for_the_proof_test";

/** The gateway's half, written out independently of the SDK. */
const digestOf = (bearer) => "sha256:" + createHash("sha256").update(bearer).digest("hex");
const keyOf = (digest) => createHash("sha256").update("permaura-bearer-key:" + digest).digest("hex");
const proofOf = (digest, port, challenge) => createHmac("sha256", digest).update(`permaura-bearer-proof:${port}:${challenge}`).digest("hex");

/** A loopback listener answering `/health` as a Permaura gateway, with the proof for `holds` when given one, and every other path with an empty capability list; it records every request. */
async function listener(holds, { none = false } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method, path: req.url, authorization: req.headers.authorization, body });
      const headers = { "content-type": "application/json" };
      if (req.url === "/health") {
        const challenge = req.headers["x-permaura-challenge"];
        if (holds && challenge && req.headers["x-permaura-bearer-key"] === keyOf(digestOf(holds))) {
          headers["x-permaura-bearer-proof"] = proofOf(digestOf(holds), server.address().port, challenge);
        } else if (none && challenge) {
          headers["x-permaura-bearer-proof"] = "none";
        }
        res.writeHead(200, headers);
        return res.end(JSON.stringify({ status: "ok", service: "permaura-gateway" }));
      }
      res.writeHead(200, headers);
      res.end(JSON.stringify({ capabilities: [] }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

// The SDK holds whatever bearer it is given, an agent's or the operator's, and on this machine sends it only to the listener that proves it stores it.
test("a listener on this machine that cannot prove it holds the bearer is sent nothing", async () => {
  for (const holds of [null, "tok_some_other_bearer"]) {
    const squatter = await listener(holds);
    try {
      const client = new PermauraClient({ baseUrl: squatter.url, token: TOKEN });
      await assert.rejects(client.listCapabilities(), (err) => {
        assert.ok(err instanceof PermauraApiError);
        assert.equal(err.code, "listener_unproven");
        assert.match(err.message, /nothing was sent/);
        assert.match(err.message, /older than 1\.3\.56/);
        return true;
      });
      assert.ok(squatter.seen.length > 0);
      for (const r of squatter.seen) {
        assert.equal(r.path, "/health");
        assert.equal(r.authorization, undefined);
        assert.ok(!JSON.stringify(r).includes(TOKEN));
      }
    } finally {
      await squatter.close();
    }
  }
});

test("the gateway that proves it holds the bearer gets it", async () => {
  const gateway = await listener(TOKEN);
  try {
    const client = new PermauraClient({ baseUrl: gateway.url, token: TOKEN });
    assert.deepEqual(await client.listCapabilities(), { capabilities: [] });
    const sent = gateway.seen.filter((r) => r.path !== "/health");
    assert.equal(sent.length, 1);
    assert.equal(sent[0].authorization, `Bearer ${TOKEN}`);
    assert.ok(gateway.seen.some((r) => r.path === "/health" && r.authorization === undefined));
  } finally {
    await gateway.close();
  }
});

// The vectors permaura-core's health_proof tests pin, so the gateway and the SDK agree byte for byte.
test("the SDK computes the gateway's bearer proof vectors", async () => {
  const digest = await bearerDigest("ENRL-TEST-VECT-OR00-0000-0000-0000-0000-0000");
  assert.equal(digest, "sha256:405283dfd17c92b452c30a21e0de754202b76d2cb7a61580f3d06e5771b7cfc1");
  assert.equal(await bearerKey(digest), "fb242f590b12bc7ab2b3f67e0de1e5ca705f266fe508c8abe77967510f797db0");
  assert.equal(await bearerProof(digest, 7376, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"), "7e3d8599336f829b37c33d8ac496f5b99749a809f6fa9b9694aae9411958dbff");
});

// A current gateway that holds no such bearer says so, and the SDK names that cause.
test("a gateway that does not hold the bearer is told apart from a listener that gives no proof", async () => {
  const gateway = await listener(null, { none: true });
  try {
    const client = new PermauraClient({ baseUrl: gateway.url, token: TOKEN });
    await assert.rejects(client.listCapabilities(), (err) => {
      assert.ok(err instanceof PermauraApiError);
      assert.equal(err.code, "bearer_not_held");
      assert.match(err.message, /does not hold this bearer/);
      return true;
    });
    assert.ok(gateway.seen.every((r) => r.path === "/health" && r.authorization === undefined));
  } finally {
    await gateway.close();
  }
});

// A runtime that cannot reach this machine directly (no process.getBuiltinModule) cannot ask for the proof, so a bearer bound for loopback is refused rather than handed to whatever holds the port through fetch.
test("a runtime with no direct path to this machine sends a bearer nothing", async () => {
  const { spawn } = await import("node:child_process");
  const squatter = await listener(null);
  try {
    const index = new URL("../dist/index.js", import.meta.url).href;
    const script = `
      delete process.getBuiltinModule;
      const { PermauraClient } = await import(${JSON.stringify(index)});
      try {
        await new PermauraClient({ baseUrl: ${JSON.stringify(squatter.url)}, token: ${JSON.stringify(TOKEN)} }).listCapabilities();
        process.stdout.write("sent");
      } catch (err) {
        process.stdout.write(JSON.stringify({ code: err.code, message: err.message }));
      }
    `;
    const out = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", script]);
      let stdout = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.on("error", reject);
      child.on("close", () => resolve(stdout));
    });
    assert.notEqual(out, "sent", "the bearer went out through fetch");
    const err = JSON.parse(out);
    assert.equal(err.code, "listener_unproven");
    assert.match(err.message, /20\.16/);
    assert.equal(squatter.seen.length, 0, "nothing reached the listener");
  } finally {
    await squatter.close();
  }
});
