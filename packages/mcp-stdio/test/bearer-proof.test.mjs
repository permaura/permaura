import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHash, createHmac } from "node:crypto";

import { GatewayClient, bearerDigest, bearerKey, bearerProof } from "../dist/index.js";

const TOKEN = "tok_agent_bearer_for_the_proof_test";
const TOOLS = JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [{ name: "permaura_invoke" }] } });

/** The gateway's half, written out independently of the bridge: the digest it keeps for a bearer, the key a client names it by, and the proof keyed on the digest. */
const digestOf = (bearer) => "sha256:" + createHash("sha256").update(bearer).digest("hex");
const keyOf = (digest) => createHash("sha256").update("permaura-bearer-key:" + digest).digest("hex");
const proofOf = (digest, port, challenge) => createHmac("sha256", digest).update(`permaura-bearer-proof:${port}:${challenge}`).digest("hex");

/** A loopback listener answering `/health` as a Permaura gateway, with the proof for `holds` when it is given one (or, with `none`, the current gateway's answer for a key it holds nothing for; with `wrong`, a proof keyed on something else), and every other path with a tools list; it records every request. */
async function listener(holds, { none = false, wrong = false } = {}) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method, path: req.url, authorization: req.headers.authorization, body });
      const headers = { "content-type": "application/json" };
      if (req.url === "/health") {
        const port = server.address().port;
        const challenge = req.headers["x-permaura-challenge"];
        if (holds && challenge && req.headers["x-permaura-bearer-key"] === keyOf(digestOf(holds))) {
          headers["x-permaura-bearer-proof"] = proofOf(digestOf(holds), port, challenge);
        } else if (none && challenge) {
          headers["x-permaura-bearer-proof"] = "none";
        } else if (wrong && challenge) {
          headers["x-permaura-bearer-proof"] = proofOf(digestOf("tok_squatters_own"), port, challenge);
        }
        res.writeHead(200, headers);
        return res.end(JSON.stringify({ status: "ok", service: "permaura-gateway" }));
      }
      res.writeHead(200, headers);
      res.end(TOOLS);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

// Another account that binds the gateway's port while it is down gets nothing: the bridge asks for the proof first and sends its token only to a listener that gives it.
test("a listener that cannot prove it holds the agent's token is sent nothing", async () => {
  for (const holds of [null, "tok_some_other_bearer"]) {
    const squatter = await listener(holds);
    try {
      const client = new GatewayClient({ baseUrl: squatter.url, token: TOKEN });
      assert.equal(await client.listTools(), null, "the bridge falls back to its static tools");
      await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), (err) => {
        assert.equal(err.mayHaveRun, false);
        assert.match(err.message, /gave no proof/);
        assert.match(err.message, /older than 1\.3\.56/, "names the gateway it needs");
        assert.match(err.message, /nothing was sent/);
        return true;
      });
      assert.ok(squatter.seen.length > 0, "it was asked");
      for (const r of squatter.seen) {
        assert.equal(r.path, "/health", `only the challenge went out: ${r.method} ${r.path}`);
        assert.equal(r.authorization, undefined);
        assert.ok(!JSON.stringify(r).includes(TOKEN), "the token never left the bridge");
      }
    } finally {
      await squatter.close();
    }
  }
});

test("the gateway that proves it holds the agent's token gets the token", async () => {
  const gateway = await listener(TOKEN);
  try {
    const client = new GatewayClient({ baseUrl: gateway.url, token: TOKEN });
    assert.deepEqual(await client.listTools(), [{ name: "permaura_invoke" }]);
    const sent = gateway.seen.filter((r) => r.path !== "/health");
    assert.equal(sent.length, 1);
    assert.equal(sent[0].authorization, `Bearer ${TOKEN}`);
    const asked = gateway.seen.filter((r) => r.path === "/health");
    assert.ok(asked.length >= 1 && asked.every((r) => r.authorization === undefined && !JSON.stringify(r).includes(TOKEN)));
  } finally {
    await gateway.close();
  }
});

// The vectors permaura-core's health_proof tests pin, so the gateway and the bridge agree byte for byte.
test("the bridge computes the gateway's bearer proof vectors", () => {
  const digest = bearerDigest("ENRL-TEST-VECT-OR00-0000-0000-0000-0000-0000");
  assert.equal(digest, "sha256:405283dfd17c92b452c30a21e0de754202b76d2cb7a61580f3d06e5771b7cfc1");
  assert.equal(bearerKey(digest), "fb242f590b12bc7ab2b3f67e0de1e5ca705f266fe508c8abe77967510f797db0");
  assert.equal(bearerProof(digest, 7376, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"), "7e3d8599336f829b37c33d8ac496f5b99749a809f6fa9b9694aae9411958dbff");
  assert.equal(digest, digestOf("ENRL-TEST-VECT-OR00-0000-0000-0000-0000-0000"));
});

// The three ways a proof is refused read differently, and the bridge says which at startup.
test("a current gateway that holds no such token says so, and the bridge says to enrol again", async () => {
  const gateway = await listener(null, { none: true });
  try {
    const client = new GatewayClient({ baseUrl: gateway.url, token: TOKEN });
    await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), (err) => {
      assert.equal(err.mayHaveRun, false);
      assert.match(err.message, /does not hold this agent's token/);
      assert.match(err.message, /permaura agent enroll/);
      assert.match(err.message, /Nothing was sent/);
      return true;
    });
    assert.match(await client.checkGateway(), /does not hold this agent's token/, "the startup check names it too");
    assert.ok(gateway.seen.every((r) => r.path === "/health" && r.authorization === undefined));
  } finally {
    await gateway.close();
  }
});

test("a proof keyed on something else is a different listener, and is refused as one", async () => {
  const squatter = await listener(null, { wrong: true });
  try {
    const client = new GatewayClient({ baseUrl: squatter.url, token: TOKEN });
    await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), /does not match/);
    assert.ok(squatter.seen.every((r) => r.path === "/health" && r.authorization === undefined));
  } finally {
    await squatter.close();
  }
});

test("the startup check is silent for the gateway that proves it holds the token", async () => {
  const gateway = await listener(TOKEN);
  try {
    assert.equal(await new GatewayClient({ baseUrl: gateway.url, token: TOKEN }).checkGateway(), undefined);
  } finally {
    await gateway.close();
  }
});
