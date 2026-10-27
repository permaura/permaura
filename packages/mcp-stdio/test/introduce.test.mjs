import { test } from "node:test";
import assert from "node:assert/strict";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { GatewayClient, createBridgeServer } from "../dist/index.js";

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A fetch that records every `/mcp` body and answers from `respond(body)`. */
function recorder(respond) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ path: new URL(url).pathname, body, authorization: init.headers.authorization });
    return respond(body);
  };
  return { calls, fetch };
}

const answer = (body) =>
  body?.method === "tools/list"
    ? json(200, { jsonrpc: "2.0", id: body.id, result: { tools: [] } })
    : json(200, { jsonrpc: "2.0", id: body?.id ?? null, result: {} });

test("the bridge passes on the client's name in its own initialize before anything else reaches the gateway", async () => {
  const { calls, fetch } = recorder(answer);
  const { server } = createBridgeServer({ fetch, token: "ENRL-TEST" });
  const client = new Client({ name: "claude-code", version: "2.0.0", title: "Claude Code" });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);
  await client.listTools();
  await client.close();

  assert.deepEqual(calls.map((c) => c.body.method), ["initialize", "tools/list"]);
  assert.deepEqual(calls[0].body.params.clientInfo, { name: "claude-code", version: "2.0.0", title: "Claude Code" });
  assert.equal(calls[0].authorization, "Bearer ENRL-TEST");
});

test("a bridge holding no token introduces nobody", async () => {
  const { calls, fetch } = recorder(answer);
  const gateway = new GatewayClient({ fetch });
  assert.equal(await gateway.introduce({ name: "cursor-vscode", version: "1.7" }), undefined);
  await gateway.listTools();
  assert.deepEqual(calls.map((c) => c.body.method), ["tools/list"]);
});

test("the gateway's refusal of the token at initialize is handed back, and the next call is still sent", async () => {
  const { calls, fetch } = recorder((body) =>
    body.method === "initialize"
      ? json(200, { jsonrpc: "2.0", id: 0, error: { code: -32000, message: "allowance exceeded: this gateway has no room for another agent" } })
      : answer(body),
  );
  const gateway = new GatewayClient({ fetch, token: "ENRL-TEST" });
  assert.match(await gateway.introduce({ name: "codex-mcp-client", version: "0.1" }), /^allowance exceeded/);
  await gateway.callTool("permaura_list_capabilities", {});
  assert.deepEqual(calls.map((c) => c.body.method), ["initialize", "tools/call"]);
});

test("a call made while the introduction is in flight waits for it, and one the gateway never answers is no refusal", async () => {
  let release;
  const held = new Promise((resolve) => (release = resolve));
  const order = [];
  const fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    order.push(`sent ${body.method}`);
    if (body.method === "initialize") {
      await held;
      throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } });
    }
    return answer(body);
  };
  const gateway = new GatewayClient({ fetch, token: "ENRL-TEST" });
  const introduced = gateway.introduce({ name: "claude-code", version: "2.0.0" });
  const listed = gateway.listTools();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(order, ["sent initialize"], "tools/list waits");
  release();
  assert.equal(await introduced, undefined);
  assert.deepEqual(await listed, []);
  assert.deepEqual(order, ["sent initialize", "sent tools/list"]);
});
