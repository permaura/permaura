import { test } from "node:test";
import assert from "node:assert/strict";

import { GatewayClient, GatewayError, DEFAULT_TIMEOUT_MS, PERMAURA_TOOLS } from "../dist/index.js";

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** A fetch that records every request and answers from `respond(url, init, n)`. */
function recorder(respond) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ path: new URL(url).pathname, search: new URL(url).search, body: init.body ? JSON.parse(init.body) : undefined, init });
    return respond(new URL(url).pathname, init, calls.length);
  };
  return { calls, fetch };
}

const networkError = (code) => Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error(code), { code }) });

const hangUntilAborted = (_path, init) =>
  new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  });

test("the default timeout outlasts the gateway's 120 s request timeout", () => {
  assert.ok(DEFAULT_TIMEOUT_MS > 120_000);
});

test("a timeout after the call was sent is reported as unknown and never re-sent", async () => {
  const { calls, fetch } = recorder(hangUntilAborted);
  const client = new GatewayClient({ fetch, timeoutMs: 20 });
  await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), (err) => {
    assert.ok(err instanceof GatewayError);
    assert.equal(err.mayHaveRun, true);
    assert.match(err.message, /may still have run/);
    return true;
  });
  assert.deepEqual(calls.map((c) => c.path), ["/mcp"]);
});

test("a dropped connection is reported as unknown and never re-sent", async () => {
  const { calls, fetch } = recorder(() => Promise.reject(networkError("ECONNRESET")));
  const client = new GatewayClient({ fetch });
  await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), (err) => err.mayHaveRun === true);
  assert.deepEqual(calls.map((c) => c.path), ["/mcp"]);
});

test("a refused connection says nothing was sent", async () => {
  const { calls, fetch } = recorder(() => Promise.reject(networkError("ECONNREFUSED")));
  const client = new GatewayClient({ fetch });
  await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }), (err) => {
    assert.equal(err.mayHaveRun, false);
    assert.match(err.message, /Nothing was sent/);
    return true;
  });
  assert.equal(calls.length, 1);
});

test("a 5xx from /mcp is returned as an unknown outcome, not retried over REST", async () => {
  const { calls, fetch } = recorder(() => json(504, { error: "the gateway cancelled this request after 120000ms" }));
  const client = new GatewayClient({ fetch });
  const res = await client.callTool("permaura_invoke", { capability: "x.y" });
  assert.equal(res.isError, true);
  assert.equal(res.data.status, 504);
  assert.match(res.data.note, /may still have run/);
  assert.deepEqual(calls.map((c) => c.path), ["/mcp"]);
});

test("only a 404 from /mcp moves a call to REST, and only that call", async () => {
  const { calls, fetch } = recorder((path, _init, n) => {
    if (path === "/mcp" && n === 1) return json(404, { error: "not found" });
    if (path === "/mcp") return json(200, { jsonrpc: "2.0", id: 1, result: { content: [] } });
    return json(200, { decision: "allow" });
  });
  const client = new GatewayClient({ fetch });
  const first = await client.callTool("permaura_invoke", { capability: "x.y", params: { a: 1 } });
  assert.deepEqual(first, { data: { decision: "allow" }, isError: false });
  await client.callTool("permaura_invoke", { capability: "x.y" });
  assert.deepEqual(calls.map((c) => c.path), ["/mcp", "/v1/invoke", "/mcp"]);
  assert.deepEqual(calls[1].body, { capability: "x.y", params: { a: 1 } });
});

test("a failed call does not move later calls off /mcp", async () => {
  const { calls, fetch } = recorder((path, init, n) =>
    n === 1 ? hangUntilAborted(path, init) : json(200, { jsonrpc: "2.0", id: 1, result: { content: [] } }),
  );
  const client = new GatewayClient({ fetch, timeoutMs: 20 });
  await assert.rejects(client.callTool("permaura_invoke", { capability: "x.y" }));
  const later = await client.callTool("permaura_invoke", { capability: "x.y" });
  assert.equal(later.isError, false);
  assert.deepEqual(calls.map((c) => c.path), ["/mcp", "/mcp"]);
});

test("explain_denial is never sent to the REST invoke endpoint", async () => {
  const { calls, fetch } = recorder(() => json(404, { error: "not found" }));
  const client = new GatewayClient({ fetch });
  await assert.rejects(client.callTool("permaura_explain_denial", { capability: "x.y" }), (err) => {
    assert.equal(err.mayHaveRun, false);
    return true;
  });
  assert.deepEqual(calls.map((c) => c.path), ["/mcp"]);
});

test("the static explain_denial advertisement does not promise a dry run", () => {
  const explain = PERMAURA_TOOLS.find((t) => t.name === "permaura_explain_denial");
  assert.ok(explain);
  assert.doesNotMatch(explain.description, /does not execute/i);
  assert.deepEqual(Object.keys(explain.inputSchema.properties), ["capability"]);
});

test("the agent token is sent as the bearer", async () => {
  const { calls, fetch } = recorder(() => json(200, { jsonrpc: "2.0", id: 1, result: { content: [] } }));
  const client = new GatewayClient({ fetch, token: "ENRL-TEST" });
  await client.callTool("permaura_list_capabilities", {});
  assert.equal(calls[0].init.headers.authorization, "Bearer ENRL-TEST");
});

test("every static tool that reads arguments declares that it takes no other, and one that reads none promises no refusal", () => {
  for (const tool of PERMAURA_TOOLS) {
    const reads = Object.keys(tool.inputSchema.properties).length > 0;
    assert.equal(tool.inputSchema.additionalProperties, reads ? false : undefined, tool.name);
  }
  const grant = PERMAURA_TOOLS.find((t) => t.name === "permaura_request_grant");
  assert.deepEqual(Object.keys(grant.inputSchema.properties), ["connection", "capabilities"]);
});

test("list_capabilities over REST sends no filter, since the tool reads no argument", async () => {
  const { calls, fetch } = recorder((path) => (path === "/mcp" ? json(404, { error: "not found" }) : json(200, { capabilities: [] })));
  const client = new GatewayClient({ fetch });
  await client.callTool("permaura_list_capabilities", { scope: "all", connector: "github", random_string: "x" });
  assert.deepEqual(calls.map((c) => [c.path, c.search]), [["/mcp", ""], ["/v1/capabilities", ""]]);
});

test("request_grant and revoke_session are not sent to an operator-only REST route", async () => {
  for (const [name, args] of [
    ["permaura_request_grant", { connection: "braintree_production" }],
    ["permaura_revoke_session", { session_id: "sess_x" }],
  ]) {
    const { calls, fetch } = recorder(() => json(404, { error: "not found" }));
    const client = new GatewayClient({ fetch });
    await assert.rejects(client.callTool(name, args));
    assert.deepEqual(calls.map((c) => c.path), ["/mcp"], name);
  }
});
