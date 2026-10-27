/**
 * Thin HTTP client to the local Permaura gateway. The bridge forwards each `tools/call` here; the gateway is what actually identifies the session, checks policy, injects the secret, executes, redacts, and audits.
 *
 * Every call goes to the gateway's MCP endpoint at `POST /mcp`. Only a 404 from `/mcp`, which means the gateway has no such endpoint and ran nothing, sends a call to the REST surface under `/v1` instead. A call is never sent twice: once a request may have reached the gateway (a timeout, a dropped connection, a 5xx), the outcome is reported as unknown rather than retried, because the gateway keeps executing after the caller hangs up.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { isIP } from "node:net";

export interface GatewayClientOptions {
  /** Gateway base URL. Defaults to the local gateway. */
  baseUrl?: string;
  /** This agent's own bearer token (never the operator token). */
  token?: string;
  /** Override fetch (tests). */
  fetch?: typeof fetch;
  /** How long a tool call may take before the bridge gives up on it, in ms. Defaults to {@link DEFAULT_TIMEOUT_MS}. */
  timeoutMs?: number;
}

export const DEFAULT_GATEWAY_URL = "http://127.0.0.1:7376";

/** Above the gateway's own 120 s request timeout, so the gateway's answer (its own 504 included) arrives before the bridge stops listening. */
export const DEFAULT_TIMEOUT_MS = 150_000;

/** The longest a request waits for the bridge's introduction before it is sent anyway, so a gateway slow to answer it never pushes a call past the MCP client's own timeout. */
const INTRODUCTION_WAIT_MS = 5_000;

/** Listing tools runs nothing, so a slow answer only costs the static list. */
const LIST_TIMEOUT_MS = 30_000;

/** Result of forwarding a tool call: a content payload plus whether the gateway flagged it as an error. */
export interface GatewayToolResult {
  /** Arbitrary JSON the gateway returned for the tool call. */
  data: unknown;
  isError: boolean;
}

export class GatewayError extends Error {
  readonly status?: number;
  /** True when the request may have reached the gateway before it failed, so the call may have run. */
  readonly mayHaveRun: boolean;
  constructor(message: string, status?: number, mayHaveRun = false) {
    super(message);
    this.name = "GatewayError";
    this.status = status;
    this.mayHaveRun = mayHaveRun;
  }
}

const MAY_HAVE_RUN =
  "The call may still have run, so it was not sent again. Check the gateway's activity log before you retry it.";

/** Failures that happen before a connection exists, so the request provably never left this machine. */
const NOT_SENT_CODES = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "EADDRNOTAVAIL",
  "UND_ERR_CONNECT_TIMEOUT",
]);

/** The part of `fetch` this client uses, so a gateway on this machine can be reached without it. */
type Exchange = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal: AbortSignal },
) => Promise<{ status: number; ok: boolean; text(): Promise<string> }>;

/**
 * The address to connect to when `hostname` (as `URL` normalizes it) names this machine, or null when it does not. `localhost` names go to 127.0.0.1, where the gateway listens, rather than wherever the resolver sends them (::1 first on macOS, where any process may hold the same port).
 */
function loopbackAddress(hostname: string): string | null {
  const host = hostname.replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return "127.0.0.1";
  if (isIP(host) === 4) return host.startsWith("127.") ? host : null;
  if (host === "::1") return host;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    return hi >> 8 === 127 ? `127.${hi & 0xff}.${lo >> 8}.${lo & 0xff}` : null;
  }
  return null;
}

/** One request to a listener on this machine at `address`, on its own agent, which never consults HTTP_PROXY, and without following redirects. */
function directExchange(address: string): Exchange {
  return (url, init) =>
    new Promise((resolve, reject) => {
      const target = new URL(url);
      const secure = target.protocol === "https:";
      const req = (secure ? https : http).request(
        {
          host: address,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search,
          method: init.method,
          headers: { ...init.headers, host: target.host },
          signal: init.signal,
          agent: false,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          resolve({
            status,
            ok: status >= 200 && status < 300,
            text: () =>
              new Promise<string>((done, fail) => {
                const chunks: Buffer[] = [];
                res.on("data", (c: Buffer) => chunks.push(c));
                res.on("end", () => done(new TextDecoder().decode(Buffer.concat(chunks))));
                res.on("error", fail);
                res.on("close", () => {
                  if (!res.complete) fail(Object.assign(new Error("the connection closed before the response ended"), { code: "ECONNRESET" }));
                });
              }),
          });
        },
      );
      req.on("error", reject);
      req.end(init.body);
    });
}

/**
 * The digest a gateway keeps in place of a bearer: `sha256:` and the lowercase hex SHA-256 of its bytes. With {@link bearerKey} and {@link bearerProof}, the client half of the gateway's `/health` bearer proof (`permaura_core::health_proof`).
 */
export function bearerDigest(bearer: string): string {
  return "sha256:" + createHash("sha256").update(bearer, "utf8").digest("hex");
}

/** What the bridge sends to name the bearer whose digest it holds. One-way: a listener that receives it cannot work back to the digest the proof is keyed on. */
export function bearerKey(digest: string): string {
  return createHash("sha256").update("permaura-bearer-key:").update(digest).digest("hex");
}

/** The proof a gateway listening on `port` and storing the bearer whose digest is `digest` gives for `challenge`. */
export function bearerProof(digest: string, port: number, challenge: string): string {
  return createHmac("sha256", digest).update(`permaura-bearer-proof:${port}:${challenge}`).digest("hex");
}

/** How long the bridge waits for a listener's `/health` proof before treating it as not given. */
const PROOF_TIMEOUT_MS = 5_000;

/**
 * What asking a listener on this machine for the bearer proof found: it gave it; a current gateway said it holds no such token (`none`); it gave a proof keyed on something else; it gave none at all (a gateway older than the check, or not a gateway); or nothing could be reached and nothing was sent.
 */
type ProofVerdict =
  | { kind: "proven" }
  | { kind: "not-held" }
  | { kind: "mismatch" }
  | { kind: "no-proof" }
  | { kind: "unreachable"; code: string };

/** The first gateway release that answers the bearer proof, named in the refusal a listener without it gets. */
const PROOF_SINCE = "1.3.56";

/**
 * Ask the listener at `address` to prove, on `/health`, that it stores `token`, with a fresh challenge and the token's key and never the token itself. Another account can bind the gateway's port while the gateway is down; only a process holding the digest the gateway keeps for the token (the gateway, or a copy of its data) can answer, because the proof is keyed on that digest, and the port is in the message so the challenge cannot be relayed to a gateway on another port.
 */
function proveBearer(address: string, target: URL, token: string, timeoutMs: number): Promise<ProofVerdict> {
  const secure = target.protocol === "https:";
  const port = Number(target.port || (secure ? 443 : 80));
  const challenge = randomBytes(32).toString("hex");
  const digest = bearerDigest(token);
  return new Promise((resolve) => {
    const req = (secure ? https : http).request(
      {
        host: address,
        port,
        path: "/health",
        method: "GET",
        headers: { host: target.host, "x-permaura-challenge": challenge, "x-permaura-bearer-key": bearerKey(digest) },
        timeout: timeoutMs,
        agent: false,
      },
      (res) => {
        res.resume();
        const offered = res.headers["x-permaura-bearer-proof"];
        if (typeof offered !== "string") return resolve({ kind: "no-proof" });
        if (offered.trim() === "none") return resolve({ kind: "not-held" });
        const expected = Buffer.from(bearerProof(digest, port, challenge));
        const given = Buffer.from(offered.trim());
        resolve(given.length === expected.length && timingSafeEqual(given, expected) ? { kind: "proven" } : { kind: "mismatch" });
      },
    );
    req.on("timeout", () => req.destroy(Object.assign(new Error("timed out"), { code: "ETIMEDOUT" })));
    req.on("error", (err) => {
      const code = errorCode(err);
      resolve(code && NOT_SENT_CODES.has(code) ? { kind: "unreachable", code } : { kind: "no-proof" });
    });
    req.end();
  });
}

/** Why nothing was sent to `baseUrl`, for a verdict other than proven, or `undefined` when it was. */
function refusalFor(baseUrl: string, verdict: ProofVerdict): string | undefined {
  switch (verdict.kind) {
    case "proven":
      return undefined;
    case "unreachable":
      return `Could not reach the Permaura gateway at ${baseUrl} (${verdict.code}). Nothing was sent; is the gateway running?`;
    case "not-held":
      return `The Permaura gateway at ${baseUrl} does not hold this agent's token: it was revoked, has expired, or the agent was removed. Nothing was sent. Enrol the agent again (permaura agent enroll, or Connect agent in the console) and give the bridge the new token.`;
    case "mismatch":
      return `Refusing to send this agent's token to ${baseUrl}: what answers there gave a proof that does not match it, so it is another program or another gateway, and nothing was sent.`;
    case "no-proof":
      return `Refusing to send this agent's token to ${baseUrl}: what answers there gave no proof that it holds the token, so nothing was sent. A Permaura gateway older than ${PROOF_SINCE} cannot give it: upgrade the gateway (permaura upgrade, or update the desktop app). Otherwise another program holds that port.`;
  }
}

function errorCode(err: unknown): string | undefined {
  for (let e: unknown = err, depth = 0; e && typeof e === "object" && depth < 4; depth++) {
    const code = (e as { code?: unknown }).code;
    if (typeof code === "string") return code;
    e = (e as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * Map each fixed `permaura_*` tool to the REST endpoint used when the gateway has no `/mcp`. `permaura_explain_denial` has no entry on purpose: `POST /v1/invoke` runs the capability, so the only place to ask for an explanation is `/mcp`. Nor do `permaura_request_grant` and `permaura_revoke_session`: the REST routes for grants and for revoking a session are the operator's, and refuse an agent's token.
 */
const REST_ROUTES: Record<string, { method: string; path: (args: Record<string, unknown>) => string; body?: (args: Record<string, unknown>) => unknown; query?: (args: Record<string, unknown>) => Record<string, unknown> }> = {
  "permaura_list_capabilities": {
    method: "GET",
    path: () => "/v1/capabilities",
  },
  "permaura_invoke": {
    method: "POST",
    path: () => "/v1/invoke",
    body: (a) => ({ capability: a.capability, params: a.params ?? {}, reason: a.reason }),
  },
  "permaura_http_request": {
    method: "POST",
    path: () => "/v1/invoke",
    // The generic proxy is expressed as a reserved capability id on the invoke endpoint.
    body: (a) => ({
      capability: "http.request",
      params: { method: a.method, url: a.url, headers: a.headers, body: a.body },
    }),
  },
  "permaura_get_approval_status": {
    method: "GET",
    path: (a) => `/v1/approvals/${encodeURIComponent(String(a.approval_id))}`,
  },
};

export class GatewayClient {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly fetchImpl: Exchange;
  private readonly fetchInjected: boolean;
  private readonly timeoutMs: number;
  /** The bridge's own `initialize` to the gateway, which every later request waits for, so the code it carries is redeemed under the client's name rather than by whichever request reaches the gateway first. */
  private introduction: Promise<unknown> = Promise.resolve();

  constructor(options: GatewayClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_GATEWAY_URL).replace(/\/+$/, "");
    this.token = options.token;
    const resolvedFetch = options.fetch ?? globalThis.fetch;
    if (!resolvedFetch) {
      throw new Error("No fetch implementation available (need Node >= 18 or an injected fetch).");
    }
    this.fetchImpl = resolvedFetch;
    this.fetchInjected = options.fetch !== undefined;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.token) h["authorization"] = `Bearer ${this.token}`;
    return h;
  }

  /** One HTTP exchange, never retried. Throws {@link GatewayError}, with `mayHaveRun` set unless the request provably never left this machine. */
  private async fetchJson(
    method: string,
    path: string,
    timeoutMs: number,
    body?: unknown,
    query?: Record<string, unknown>,
  ): Promise<{ status: number; ok: boolean; json: unknown }> {
    const url = new URL(this.baseUrl + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }
    // With NODE_USE_ENV_PROXY set, Node's fetch tunnels even 127.0.0.1 through HTTP_PROXY, handing the proxy this agent's bearer.
    const local = this.fetchInjected ? null : loopbackAddress(url.hostname);
    const exchange = local ? directExchange(local) : this.fetchImpl;
    // Asked before every request that carries the token, since whoever holds the port can change between two of them. The proof and the request are two connections, so a listener swapped in the instant between them is not caught: the bound the CLI's proof has too.
    if (local && this.token) {
      const refusal = refusalFor(this.baseUrl, await proveBearer(local, url, this.token, Math.min(timeoutMs, PROOF_TIMEOUT_MS)));
      if (refusal) throw new GatewayError(refusal);
    }
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    try {
      let res: Awaited<ReturnType<Exchange>>;
      try {
        res = await exchange(url.toString(), {
          method,
          headers: this.headers(),
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (err) {
        const code = errorCode(err);
        if (!timedOut && code && NOT_SENT_CODES.has(code)) {
          throw new GatewayError(
            `Could not reach the Permaura gateway at ${this.baseUrl} (${code}). Nothing was sent; is the gateway running?`,
          );
        }
        const what = timedOut
          ? `did not answer within ${Math.round(timeoutMs / 1000)} s`
          : `dropped the connection (${code ?? (err instanceof Error ? err.message : String(err))})`;
        throw new GatewayError(`The Permaura gateway at ${this.baseUrl} ${what}. ${MAY_HAVE_RUN}`, undefined, true);
      }
      let text: string;
      try {
        text = await res.text();
      } catch (err) {
        const what = timedOut ? "timed out" : `failed (${errorCode(err) ?? (err instanceof Error ? err.message : String(err))})`;
        throw new GatewayError(
          `The Permaura gateway answered ${res.status}, but reading its response ${what}. ${MAY_HAVE_RUN}`,
          res.status,
          true,
        );
      }
      let json: unknown = undefined;
      if (text) {
        try {
          json = JSON.parse(text);
        } catch {
          json = text;
        }
      }
      return { status: res.status, ok: res.ok, json };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Ask the gateway on this machine for the bearer proof, as every request carrying the token does, and say why a request would be refused, or `undefined` when it would be sent (or the gateway is not on this machine, where TLS vouches instead). The bridge writes the answer to stderr at startup, since a refused `tools/list` otherwise shows only as the static tool list.
   */
  async checkGateway(): Promise<string | undefined> {
    if (!this.token || this.fetchInjected) return undefined;
    const url = new URL(this.baseUrl + "/health");
    const local = loopbackAddress(url.hostname);
    if (!local) return undefined;
    return refusalFor(this.baseUrl, await proveBearer(local, url, this.token, PROOF_TIMEOUT_MS));
  }

  /**
   * Tell the gateway which MCP client is behind this bridge, as a client connected to the gateway directly does in its own `initialize`, so an enrolment code the bridge holds enrols its agent under that client's name. Requests made after this wait for it. Best effort: an answer the gateway cannot give is left for the next call to meet. Resolves to the gateway's refusal of the token, for the bridge to note on stderr, or `undefined`.
   */
  introduce(client: { name: string; version: string; title?: string }): Promise<string | undefined> {
    if (!this.token) return Promise.resolve(undefined);
    const clientInfo = { name: client.name, version: client.version, ...(client.title === undefined ? {} : { title: client.title }) };
    const answered = this.fetchJson("POST", "/mcp", LIST_TIMEOUT_MS, {
      jsonrpc: "2.0",
      id: 0,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo },
    }).then(
      (res) => {
        const message = (res.json as { error?: { message?: unknown } } | undefined)?.error?.message;
        return typeof message === "string" ? message : undefined;
      },
      () => undefined,
    );
    this.introduction = answered;
    return answered;
  }

  /** Wait for the introduction, for at most {@link INTRODUCTION_WAIT_MS}. */
  private async introduced(): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cap = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, INTRODUCTION_WAIT_MS);
    });
    try {
      await Promise.race([this.introduction, cap]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Fetch the gateway's advertised tools: the fixed `permaura_*` tools plus a dynamic tool per capability this session can reach (e.g. `fal.image.generate`). Returns `null` if the gateway has no `/mcp` endpoint or cannot be reached, so the caller can serve the static advertisement instead.
   */
  async listTools(): Promise<unknown[] | null> {
    await this.introduced();
    try {
      const res = await this.fetchJson("POST", "/mcp", LIST_TIMEOUT_MS, {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
      });
      if (!res.ok) return null;
      const envelope = res.json as { result?: { tools?: unknown[] } } | undefined;
      const tools = envelope?.result?.tools;
      return Array.isArray(tools) ? tools : null;
    } catch {
      return null;
    }
  }

  /**
   * Forward a single tool call to the gateway's `/mcp` endpoint, which handles both the fixed `permaura_*` tools and the dynamic per-capability tools. Only a 404 from `/mcp` moves the call to the REST mapping, and that decision is made per call, so one blip never moves later calls anywhere.
   */
  async callTool(name: string, args: Record<string, unknown>): Promise<GatewayToolResult> {
    await this.introduced();
    const res = await this.fetchJson("POST", "/mcp", this.timeoutMs, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    });
    if (res.status === 404) return this.callRest(name, args);
    if (!res.ok) return httpError(res.status, res.json);
    const envelope = res.json as { result?: unknown; error?: unknown } | undefined;
    if (envelope && typeof envelope === "object" && "error" in envelope && envelope.error) {
      return { data: envelope.error, isError: true };
    }
    if (envelope && typeof envelope === "object" && "result" in envelope) {
      return { data: envelope.result, isError: false };
    }
    return { data: res.json, isError: false };
  }

  private async callRest(name: string, args: Record<string, unknown>): Promise<GatewayToolResult> {
    const route = REST_ROUTES[name];
    if (!route) {
      throw new GatewayError(
        `This gateway has no /mcp endpoint, and ${name} has no REST equivalent, so it was not sent.`,
        404,
      );
    }
    const res = await this.fetchJson(
      route.method,
      route.path(args),
      this.timeoutMs,
      route.body ? route.body(args) : undefined,
      route.query ? route.query(args) : undefined,
    );
    return res.ok ? { data: res.json, isError: false } : httpError(res.status, res.json);
  }
}

/** A non-2xx answer. A 5xx can arrive after the call started (the gateway's own timeout is a 504), so the agent is told the outcome is unknown. */
function httpError(status: number, body: unknown): GatewayToolResult {
  if (status >= 500) {
    return { data: { status, error: body, note: MAY_HAVE_RUN }, isError: true };
  }
  return { data: body, isError: true };
}
