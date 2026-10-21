import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";

import { BoundedStdioServerTransport, DEFAULT_MAX_MESSAGE_BYTES, maxMessageBytesFromEnv } from "../dist/index.js";

const settle = () => new Promise((resolve) => setTimeout(resolve, 15));
const msg = (id, pad = "") => JSON.stringify({ jsonrpc: "2.0", id, method: "ping", params: { pad } });

function rig(maxMessageBytes) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const logs = [];
  const messages = [];
  const errors = [];
  let closed = 0;
  const transport = new BoundedStdioServerTransport(stdin, stdout, { maxMessageBytes, log: (l) => logs.push(l) });
  transport.onmessage = (m) => messages.push(m);
  transport.onerror = (e) => errors.push(e);
  transport.onclose = () => closed++;
  return { stdin, stdout, transport, logs, messages, errors, closed: () => closed };
}

test("the default limit is the SDK's 10 MiB", () => {
  assert.equal(DEFAULT_MAX_MESSAGE_BYTES, 10 * 1024 * 1024);
});

test("a well-formed line is delivered", async () => {
  const r = rig(1024);
  await r.transport.start();
  r.stdin.write(`${msg(1)}\n`);
  await settle();
  assert.deepEqual(r.messages.map((m) => m.id), [1]);
  assert.equal(r.errors.length, 0);
});

test("a line split across chunks under the limit is reassembled", async () => {
  const r = rig(1024);
  await r.transport.start();
  const line = `${msg(2, "abc")}\n`;
  for (let i = 0; i < line.length; i += 7) r.stdin.write(line.slice(i, i + 7));
  await settle();
  assert.deepEqual(r.messages.map((m) => m.id), [2]);
});

test("an oversized line is discarded, logged once, and the line after it in the same chunk is delivered", async () => {
  const r = rig(200);
  await r.transport.start();
  r.stdin.write(`${msg(3, "x".repeat(500))}\n${msg(4)}\n`);
  await settle();
  assert.deepEqual(r.messages.map((m) => m.id), [4]);
  assert.equal(r.logs.length, 1);
  assert.match(r.logs[0], /discarded a \d+-byte message: the limit is 200 bytes/);
  assert.equal(r.errors.length, 0);
  assert.equal(r.closed(), 0);
  assert.equal(r.stdin.isPaused(), false);
});

test("an oversized line arriving over many chunks is skipped to its newline, counted whole, then service resumes", async () => {
  const r = rig(200);
  await r.transport.start();
  for (let i = 0; i < 10; i++) r.stdin.write("y".repeat(100));
  r.stdin.write("\n");
  r.stdin.write(`${msg(5)}\n`);
  await settle();
  assert.deepEqual(r.messages.map((m) => m.id), [5]);
  assert.equal(r.logs.length, 1);
  assert.match(r.logs[0], /discarded a 1001-byte message/);
  assert.equal(r.closed(), 0);
});

test("a stream that never sends a newline is dropped chunk by chunk without growing memory", async () => {
  const r = rig(200);
  await r.transport.start();
  for (let i = 0; i < 1000; i++) r.stdin.write("z".repeat(1000));
  await settle();
  assert.equal(r.messages.length, 0);
  assert.equal(r.logs.length, 0, "nothing to report until the line ends");
  r.stdin.write(`\n${msg(6)}\n`);
  await settle();
  assert.deepEqual(r.messages.map((m) => m.id), [6]);
  assert.match(r.logs[0], /discarded a 1000001-byte message/);
});

test("malformed JSON on one line reports an error and the next line is still delivered", async () => {
  const r = rig(1024);
  await r.transport.start();
  r.stdin.write(`not json\n${msg(7)}\n`);
  await settle();
  assert.equal(r.errors.length, 1);
  assert.deepEqual(r.messages.map((m) => m.id), [7]);
});

test("send writes one newline-terminated line per message", async () => {
  const r = rig(1024);
  const out = [];
  r.stdout.on("data", (c) => out.push(c.toString()));
  await r.transport.send({ jsonrpc: "2.0", id: 8, result: {} });
  await settle();
  assert.equal(out.join(""), `${JSON.stringify({ jsonrpc: "2.0", id: 8, result: {} })}\n`);
});

test("close pauses stdin when it was the only listener and fires onclose once", async () => {
  const r = rig(1024);
  await r.transport.start();
  await r.transport.close();
  assert.equal(r.closed(), 1);
  assert.equal(r.stdin.isPaused(), true);
});

test("the environment override takes a positive integer and falls back loudly otherwise", () => {
  const warnings = [];
  const warn = (l) => warnings.push(l);
  assert.equal(maxMessageBytesFromEnv({}, warn), DEFAULT_MAX_MESSAGE_BYTES);
  assert.equal(maxMessageBytesFromEnv({ PERMAURA_MCP_MAX_MESSAGE_BYTES: "4194304" }, warn), 4194304);
  assert.equal(warnings.length, 0);
  assert.equal(maxMessageBytesFromEnv({ PERMAURA_MCP_MAX_MESSAGE_BYTES: "lots" }, warn), DEFAULT_MAX_MESSAGE_BYTES);
  assert.equal(maxMessageBytesFromEnv({ PERMAURA_MCP_MAX_MESSAGE_BYTES: "0" }, warn), DEFAULT_MAX_MESSAGE_BYTES);
  assert.equal(warnings.length, 2);
});
