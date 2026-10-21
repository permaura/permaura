import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";

import { PermauraClient, PermauraApiError, bearerDigest, bearerKey, bearerProof } from "../dist/index.js";

const TOKEN = "session-token-must-not-reach-the-proxy";

/** Answer a `/health` bearer challenge as the gateway holding TOKEN does, and say whether `req` was one; the client asks before every request that carries the bearer. */
async function answeredProof(req, res, port) {
  if (req.url !== "/health") return false;
  const challenge = req.headers["x-permaura-challenge"];
  const headers = { "content-type": "application/json" };
  const digest = await bearerDigest(TOKEN);
  if (challenge && req.headers["x-permaura-bearer-key"] === (await bearerKey(digest))) {
    headers["x-permaura-bearer-proof"] = await bearerProof(digest, port, challenge);
  }
  res.writeHead(200, headers);
  res.end(JSON.stringify({ status: "ok", service: "permaura-gateway" }));
  return true;
}

/** A gateway stand-in that records each request and answers every capability listing. */
async function fakeGateway(host) {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      if (await answeredProof(req, res, server.address().port)) return;
      seen.push({ method: req.method, path: req.url, host: req.headers.host, authorization: req.headers.authorization, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ capabilities: [] }));
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, resolve);
  });
  return { seen, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

/** A proxy that records the first line of every request it is handed and refuses it. */
async function recordingProxy() {
  const lines = [];
  const server = net.createServer((socket) => {
    socket.once("data", (d) => {
      lines.push(d.toString("utf8").split("\r\n")[0]);
      socket.end("HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n");
    });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { lines, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

/** Lists capabilities through the SDK at each base URL in a child that has HTTP_PROXY set and NODE_USE_ENV_PROXY on. */
function listEachThroughEnvProxy(proxyUrl, baseUrls) {
  const index = new URL("../dist/index.js", import.meta.url).href;
  const script = `
    const { PermauraClient } = await import(${JSON.stringify(index)});
    // A plain fetch to the proxy's own address: it arrives as a CONNECT only when this Node routes fetch through HTTP_PROXY at all.
    const honored = await fetch(${JSON.stringify(proxyUrl + "/probe")}).then(() => false, () => true);
    const out = { honored, results: [] };
    for (const baseUrl of honored ? ${JSON.stringify(baseUrls)} : []) {
      const client = new PermauraClient({ baseUrl, token: ${JSON.stringify(TOKEN)} });
      try {
        const res = await client.listCapabilities({ scope: "current_session" });
        out.results.push({ baseUrl, capabilities: res.capabilities.length });
      } catch (err) {
        out.results.push({ baseUrl, error: String(err && err.message) });
      }
    }
    process.stdout.write(JSON.stringify(out));
  `;
  const env = { ...process.env, NODE_USE_ENV_PROXY: "1", HTTP_PROXY: proxyUrl, http_proxy: proxyUrl, HTTPS_PROXY: proxyUrl, https_proxy: proxyUrl };
  delete env.NO_PROXY;
  delete env.no_proxy;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => {
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error(`child exited ${code}: ${stderr || stdout}`));
      }
    });
  });
}

// With NODE_USE_ENV_PROXY set (Node 22.21+ and 24+), the global fetch sends even http://127.0.0.1 through HTTP_PROXY, as a CONNECT tunnel the proxy terminates, so the bearer (and a createSecret value) is the proxy's to read.
test("under Node, a gateway on this machine is never reached through the environment's proxy, and every other host still is", async (t) => {
  const gw = await fakeGateway("127.0.0.1");
  const gw6 = await fakeGateway("::1").catch(() => null);
  const proxy = await recordingProxy();
  const p = gw.port;
  const loopback = [
    `http://127.0.0.1:${p}`,
    `http://localhost:${p}`,
    `http://LOCALHOST.:${p}`,
    `http://agent.localhost:${p}`,
    `http://127.1:${p}`,
    `http://[::ffff:127.0.0.1]:${p}`,
    ...(gw6 ? [`http://[::1]:${gw6.port}`, `http://[0:0:0:0:0:0:0:1]:${gw6.port}`] : []),
  ];
  const remote = [
    `http://permaura-proxy-probe.invalid:${p}`,
    `http://localhost.permaura-proxy-probe.invalid:${p}`,
    `http://128.0.0.1:${p}`,
    `http://[::ffff:10.0.0.1]:${p}`,
  ];
  try {
    const { honored, results } = await listEachThroughEnvProxy(proxy.url, [...remote, ...loopback]);
    if (!honored) {
      t.skip(`this Node (${process.version}) does not honor NODE_USE_ENV_PROXY, so there is no environment proxy to bypass`);
      return;
    }
    const proxiedHosts = new Set(proxy.lines.map((l) => l.split(" ")[1]));
    const reachedProxy = (baseUrl) => {
      const { host } = new URL(baseUrl);
      return [...proxiedHosts].some((h) => h === host || h.startsWith(`http://${host}/`));
    };
    for (const baseUrl of remote) {
      assert.ok(reachedProxy(baseUrl), `${baseUrl} should still go through the environment's proxy; the proxy saw: ${proxy.lines.join(" | ")}`);
    }
    for (const baseUrl of loopback) {
      assert.ok(!reachedProxy(baseUrl), `${baseUrl} went through the proxy: ${proxy.lines.join(" | ")}`);
      const r = results.find((x) => x.baseUrl === baseUrl);
      assert.deepEqual(r, { baseUrl, capabilities: 0 }, `${baseUrl} did not reach the gateway directly`);
    }
    assert.ok(proxy.lines.every((l) => !l.includes(TOKEN)));

    const seen = [...gw.seen, ...(gw6 ? gw6.seen : [])];
    assert.equal(seen.length, loopback.length);
    for (const r of seen) {
      assert.equal(r.method, "GET");
      assert.equal(r.path, "/v1/capabilities?scope=current_session");
      assert.equal(r.authorization, `Bearer ${TOKEN}`);
    }
    assert.ok(gw.seen.some((r) => r.host === `agent.localhost:${p}`), "the Host header keeps the name the URL used");
  } finally {
    await proxy.close();
    await gw.close();
    if (gw6) await gw6.close();
  }
});

test("a gateway on this machine gets the body and the bearer, and its error envelope is surfaced", async () => {
  const seen = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", async () => {
      if (await answeredProof(req, res, server.address().port)) return;
      seen.push({ method: req.method, path: req.url, body, authorization: req.headers.authorization, length: req.headers["content-length"] });
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "denied", message: "naïve ünïcode", reason: "floor" } }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const client = new PermauraClient({ baseUrl: `http://127.0.0.1:${server.address().port}/`, token: TOKEN });
    await assert.rejects(client.resolveApproval({ approval_id: "ap_é", decision: "deny" }), (err) => {
      assert.ok(err instanceof PermauraApiError);
      assert.equal(err.status, 403);
      assert.equal(err.code, "denied");
      assert.equal(err.message, "naïve ünïcode");
      assert.equal(err.reason, "floor");
      return true;
    });
    assert.equal(seen.length, 1);
    assert.equal(`${seen[0].method} ${seen[0].path}`, "POST /v1/approvals");
    assert.equal(seen[0].authorization, `Bearer ${TOKEN}`);
    assert.deepEqual(JSON.parse(seen[0].body), { approval_id: "ap_é", decision: "deny" });
    assert.equal(Number(seen[0].length), Buffer.byteLength(seen[0].body));
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("a redirect from a gateway on this machine is not followed", async () => {
  let elsewhere = 0;
  const target = http.createServer((_req, res) => {
    elsewhere++;
    res.end("{}");
  });
  await new Promise((resolve) => target.listen(0, "127.0.0.1", resolve));
  const server = http.createServer(async (req, res) => {
    if (await answeredProof(req, res, server.address().port)) return;
    res.writeHead(307, { location: `http://127.0.0.1:${target.address().port}/v1/capabilities` });
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const client = new PermauraClient({ baseUrl: `http://127.0.0.1:${server.address().port}`, token: TOKEN });
    await assert.rejects(client.listCapabilities(), (err) => err instanceof PermauraApiError && err.status === 307);
    assert.equal(elsewhere, 0);
  } finally {
    await new Promise((r) => server.close(r));
    await new Promise((r) => target.close(r));
  }
});

test("a closed port on this machine rejects the way fetch does, with the cause attached", async () => {
  const gw = await fakeGateway("127.0.0.1");
  const { port } = gw;
  await gw.close();
  const client = new PermauraClient({ baseUrl: `http://127.0.0.1:${port}`, token: TOKEN });
  await assert.rejects(client.listCapabilities(), (err) => {
    assert.ok(err instanceof TypeError);
    assert.equal(err.cause?.code, "ECONNREFUSED");
    return true;
  });
});

test("an injected fetch is still used for a gateway on this machine", async () => {
  const urls = [];
  const fetch = async (url) => {
    urls.push(url);
    return new Response(JSON.stringify({ capabilities: [] }), { status: 200 });
  };
  const client = new PermauraClient({ baseUrl: "http://127.0.0.1:1", fetch });
  await client.listCapabilities();
  assert.deepEqual(urls, ["http://127.0.0.1:1/v1/capabilities"]);
});
