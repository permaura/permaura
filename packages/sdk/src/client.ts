import {
  ApiErrorSchema,
  CreateSessionRequestSchema,
  CreateSessionResponseSchema,
  ListCapabilitiesResponseSchema,
  CreateGrantRequestSchema,
  CreateGrantResponseSchema,
  InvokeRequestSchema,
  InvokeResponseSchema,
  ResolveApprovalRequestSchema,
  ResolveApprovalResponseSchema,
  ListAuditEventsResponseSchema,
  CreateSecretRequestSchema,
  CreateSecretResponseSchema,
  RotateSecretRequestSchema,
  RotateSecretResponseSchema,
  EnrollDeviceRequestSchema,
  EnrollDeviceResponseSchema,
  RegisterAgentRequestSchema,
  RegisterAgentResponseSchema,
  type CreateSessionRequest,
  type CreateSessionResponse,
  type ListCapabilitiesQuery,
  type ListCapabilitiesResponse,
  type CreateGrantRequest,
  type CreateGrantResponse,
  type InvokeRequest,
  type InvokeResponse,
  type ResolveApprovalRequest,
  type ResolveApprovalResponse,
  type ListAuditEventsQuery,
  type ListAuditEventsResponse,
  type CreateSecretRequest,
  type CreateSecretResponse,
  type RotateSecretRequest,
  type RotateSecretResponse,
  type EnrollDeviceRequest,
  type EnrollDeviceResponse,
  type RegisterAgentRequest,
  type RegisterAgentResponse,
} from "@permaura/types";

/** The default local gateway address `permaura start` listens on. */
export const DEFAULT_BASE_URL = "http://127.0.0.1:7376";

/** The part of `fetch` this client uses, so a gateway on this machine can be reached without it. */
type Exchange = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ status: number; ok: boolean; statusText: string; text(): Promise<string> }>;

/** The slice of `node:http` and `node:https` used here, declared so the SDK carries no Node typings. */
interface NodeHttp {
  request(
    options: Record<string, unknown>,
    onResponse: (res: {
      statusCode?: number;
      statusMessage?: string;
      complete: boolean;
      headers?: Record<string, string | string[] | undefined>;
      on(event: string, listener: (arg?: unknown) => void): unknown;
    }) => void,
  ): {
    on(event: "error", listener: (err: Error) => void): unknown;
    on(event: "timeout", listener: () => void): unknown;
    end(body?: string): unknown;
    destroy(err?: Error): unknown;
  };
}

/**
 * The address to connect to when `hostname` (as `URL` normalizes it) names this machine, or null when it does not. `localhost` names go to 127.0.0.1, where the gateway listens, rather than wherever the resolver sends them (::1 first on macOS, where any process may hold the same port).
 */
function loopbackAddress(hostname: string): string | null {
  const host = hostname.replace(/^\[(.*)\]$/, "$1").replace(/\.$/, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return "127.0.0.1";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host.startsWith("127.") ? host : null;
  if (host === "::1") return host;
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    return hi >> 8 === 127 ? `127.${hi & 0xff}.${lo >> 8}.${lo & 0xff}` : null;
  }
  return null;
}

/**
 * Node's own HTTP modules, or null outside Node. Reached through `process.getBuiltinModule` so a browser bundle never resolves `node:http`; every Node that routes `fetch` through HTTP_PROXY (22.21+, 24+) has it.
 */
function nodeHttp(): { http: NodeHttp; https: NodeHttp } | null {
  const proc = (globalThis as { process?: { versions?: { node?: string }; getBuiltinModule?: (id: string) => unknown } }).process;
  if (!proc?.versions?.node || typeof proc.getBuiltinModule !== "function") return null;
  return { http: proc.getBuiltinModule("node:http") as NodeHttp, https: proc.getBuiltinModule("node:https") as NodeHttp };
}

const HEX = (bytes: ArrayBuffer): string => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

function subtle(): SubtleCrypto {
  const s = (globalThis as { crypto?: { subtle?: SubtleCrypto } }).crypto?.subtle;
  if (!s) throw new Error("this runtime has no Web Crypto, so the gateway's listener proof cannot be checked");
  return s;
}

/** The digest a gateway keeps in place of a bearer: `sha256:` and the lowercase hex SHA-256 of its bytes (`permaura_core::health_proof::bearer_digest`). */
export async function bearerDigest(bearer: string): Promise<string> {
  return "sha256:" + HEX(await subtle().digest("SHA-256", new TextEncoder().encode(bearer)));
}

/** What a client sends to name the bearer whose digest it holds, without revealing the digest (`bearer_key`). */
export async function bearerKey(digest: string): Promise<string> {
  return HEX(await subtle().digest("SHA-256", new TextEncoder().encode("permaura-bearer-key:" + digest)));
}

/** The proof a gateway listening on `port` and storing the bearer whose digest is `digest` gives for `challenge` (`bearer_proof`). */
export async function bearerProof(digest: string, port: number, challenge: string): Promise<string> {
  const key = await subtle().importKey("raw", new TextEncoder().encode(digest), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return HEX(await subtle().sign("HMAC", key, new TextEncoder().encode(`permaura-bearer-proof:${port}:${challenge}`)));
}

/**
 * Whether the listener on this machine at `address` proves, on `/health`, that it stores `token`, asked with a fresh challenge and the token's key and never the token. Another account can bind the gateway's port while the gateway is down; only a process holding the digest the gateway keeps for the token (the gateway, or a copy of its data) can answer, and the port in the message stops the challenge being relayed to a gateway on another port.
 */
async function listenerProvesBearer(modules: { http: NodeHttp; https: NodeHttp }, address: string, target: URL, token: string): Promise<ProofVerdict> {
  type Answer = { proof: string | null } | { failed: unknown };
  const secure = target.protocol === "https:";
  const port = Number(target.port || (secure ? 443 : 80));
  const nonce = new Uint8Array(32);
  (globalThis as { crypto: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto.getRandomValues(nonce);
  const challenge = HEX(nonce.buffer);
  const digest = await bearerDigest(token);
  const key = await bearerKey(digest);
  const answer = await new Promise<Answer>((resolve) => {
    const req = (secure ? modules.https : modules.http).request(
      {
        host: address,
        port,
        path: "/health",
        method: "GET",
        headers: { host: target.host, "x-permaura-challenge": challenge, "x-permaura-bearer-key": key },
        agent: false,
        timeout: 5_000,
      },
      (res) => {
        const header = res.headers?.["x-permaura-bearer-proof"];
        res.on("data", () => {});
        resolve({ proof: typeof header === "string" ? header.trim() : null });
      },
    );
    req.on("timeout", () => req.destroy(new Error("the listener did not answer the proof within 5 s")));
    req.on("error", (err) => resolve({ failed: err }));
    req.end();
  });
  // Nothing listening is the network failing, reported the way fetch reports it; nothing was sent.
  if ("failed" in answer) {
    const code = (answer.failed as { code?: unknown }).code;
    if (code === "ECONNREFUSED" || code === "EADDRNOTAVAIL" || code === "EHOSTUNREACH" || code === "ENETUNREACH") {
      throw new TypeError("fetch failed", { cause: answer.failed });
    }
    return "no-proof";
  }
  if (answer.proof === null) return "no-proof";
  if (answer.proof === "none") return "not-held";
  return answer.proof === (await bearerProof(digest, port, challenge)) ? "proven" : "mismatch";
}

/** What asking a listener on this machine for the bearer proof found: it gave it; a current gateway holds no such bearer; it gave a proof keyed on something else; or it gave none at all (a gateway older than the check, or not a gateway). */
type ProofVerdict = "proven" | "not-held" | "mismatch" | "no-proof";

/** The first gateway release that answers the bearer proof. */
const PROOF_SINCE = "1.3.56";

/** The refusal for a verdict other than proven: nothing is sent in any of them. */
function refusalFor(baseUrl: string, verdict: Exclude<ProofVerdict, "proven">): PermauraApiError {
  switch (verdict) {
    case "not-held":
      return new PermauraApiError(
        0,
        "bearer_not_held",
        `The Permaura gateway at ${baseUrl} does not hold this bearer: it was revoked, has expired, or its agent was removed. Nothing was sent; get a new token.`,
      );
    case "mismatch":
      return new PermauraApiError(
        0,
        "listener_unproven",
        `Refusing to send the bearer to ${baseUrl}: what answers there gave a proof that does not match it, so it is another program or another gateway, and nothing was sent.`,
      );
    case "no-proof":
      return new PermauraApiError(
        0,
        "listener_unproven",
        `Refusing to send the bearer to ${baseUrl}: what answers there gave no proof that it holds it, so nothing was sent. A Permaura gateway older than ${PROOF_SINCE} cannot give it: upgrade the gateway. Otherwise another program holds that port.`,
      );
  }
}

/** One request to a listener on this machine at `address`, on its own agent, which never consults HTTP_PROXY, and without following redirects. Failures reject as `fetch` does, a TypeError with the cause attached. */
function directExchange(modules: { http: NodeHttp; https: NodeHttp }, address: string): Exchange {
  return (url, init) =>
    new Promise((resolve, reject) => {
      const failed = (cause: unknown) => reject(new TypeError("fetch failed", { cause }));
      const target = new URL(url);
      const secure = target.protocol === "https:";
      const req = (secure ? modules.https : modules.http).request(
        {
          host: address,
          port: target.port || (secure ? 443 : 80),
          path: target.pathname + target.search,
          method: init.method,
          headers: { ...init.headers, host: target.host },
          agent: false,
        },
        (res) => {
          const status = res.statusCode ?? 0;
          resolve({
            status,
            ok: status >= 200 && status < 300,
            statusText: res.statusMessage ?? "",
            text: () =>
              new Promise<string>((done, fail) => {
                const chunks: Uint8Array[] = [];
                res.on("data", (c) => chunks.push(c as Uint8Array));
                res.on("end", () => {
                  const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
                  let at = 0;
                  for (const c of chunks) {
                    all.set(c, at);
                    at += c.length;
                  }
                  done(new TextDecoder().decode(all));
                });
                res.on("error", (err) => fail(new TypeError("terminated", { cause: err })));
                res.on("close", () => {
                  if (!res.complete) fail(new TypeError("terminated", { cause: new Error("the connection closed before the response ended") }));
                });
              }),
          });
        },
      );
      req.on("error", failed);
      req.end(init.body);
    });
}

export interface PermauraClientOptions {
  /** Gateway base URL. Defaults to the local broker at {@link DEFAULT_BASE_URL}. */
  baseUrl?: string;
  /** Bearer token (session token, device enrollment token, or API key). */
  token?: string;
  /** Inject a custom fetch (tests, non-browser runtimes). Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /** Extra headers applied to every request. */
  headers?: Record<string, string>;
}

/**
 * A typed error thrown when the gateway responds non-2xx. Carries the parsed `ApiError` envelope when one was returned (so `.reason` surfaces the policy reason for a denial) and the raw HTTP status.
 */
export class PermauraApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reason?: string;

  constructor(status: number, code: string, message: string, reason?: string) {
    super(message);
    this.name = "PermauraApiError";
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

/**
 * Typed client written for an earlier version of the Permaura REST API (v1). Every method validates against the `@permaura/types` schemas, which no longer match the gateway (see the package README), so expect validation failures.
 *
 * The client deliberately exposes no method that returns a raw secret: `createSecret`/`rotateSecret` return only a `SecretRef`. That mirrors the product invariant: you can store and rotate credentials through Permaura, never read them back out.
 *
 * @example
 * const client = new PermauraClient({ token: sessionToken });
 * const { capabilities } = await client.listCapabilities({ scope: "current_session" });
 * const res = await client.invoke({ capability: "braintree.transactions.search", params: { status: "failed" } });
 */
export class PermauraClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: Exchange;
  private readonly fetchInjected: boolean;
  private readonly baseHeaders: Record<string, string>;
  private token?: string;

  constructor(options: PermauraClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.token = options.token;
    const resolvedFetch = options.fetch ?? globalThis.fetch;
    if (!resolvedFetch) {
      throw new Error(
        "No fetch implementation available. Pass `fetch` in PermauraClientOptions or run on a platform with a global fetch (Node >= 18).",
      );
    }
    this.fetchImpl = resolvedFetch;
    this.fetchInjected = options.fetch !== undefined;
    this.baseHeaders = { "content-type": "application/json", ...(options.headers ?? {}) };
  }

  /** Update the bearer token in place, e.g. after `createSession` returns a session token. */
  setToken(token: string | undefined): void {
    this.token = token;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { ...this.baseHeaders };
    if (this.token) h["authorization"] = `Bearer ${this.token}`;
    return h;
  }

  private async request<T>(
    method: string,
    path: string,
    parse: (data: unknown) => T,
    body?: unknown,
    query?: Record<string, unknown>,
  ): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
      }
    }

    // With NODE_USE_ENV_PROXY set, Node's fetch tunnels even 127.0.0.1 through HTTP_PROXY, handing the proxy the bearer and any secret in the body.
    const local = this.fetchInjected ? null : loopbackAddress(url.hostname);
    const modules = local ? nodeHttp() : null;
    const exchange = local && modules ? directExchange(modules, local) : this.fetchImpl;
    // Asked before every request that carries the bearer, since whoever holds the port can change between two of them. The proof and the request are two connections, so a listener swapped in the instant between them is not caught: the bound the CLI's proof has too.
    if (local && this.token) {
      // No direct path means no way to ask for the proof, so the bearer is refused rather than handed through fetch to whatever holds the port.
      if (!modules) {
        throw new PermauraApiError(
          0,
          "listener_unproven",
          `Refusing to send the bearer to ${this.baseUrl}: this runtime cannot reach a gateway on this machine directly (it has no process.getBuiltinModule), so the listener cannot be asked to prove it holds the bearer, and nothing was sent. Use Node 20.16 or later.`,
        );
      }
      const verdict = await listenerProvesBearer(modules, local, url, this.token);
      if (verdict !== "proven") throw refusalFor(this.baseUrl, verdict);
    }
    const res = await exchange(url.toString(), {
      method,
      headers: this.headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    const text = await res.text();
    let json: unknown = undefined;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
    }

    if (!res.ok) {
      const parsedErr = ApiErrorSchema.safeParse(json);
      if (parsedErr.success) {
        const { code, message, reason } = parsedErr.data.error;
        throw new PermauraApiError(res.status, code, message, reason);
      }
      throw new PermauraApiError(res.status, "http_error", `HTTP ${res.status}: ${text || res.statusText}`);
    }

    return parse(json);
  }

  /** POST /v1/sessions: open an operator session (needs the operator token and a loopback caller). Never hand the result to an agent. */
  async createSession(req: CreateSessionRequest): Promise<CreateSessionResponse> {
    return this.request(
      "POST",
      "/v1/sessions",
      (d) => CreateSessionResponseSchema.parse(d),
      CreateSessionRequestSchema.parse(req),
    );
  }

  /** GET /v1/capabilities: the capabilities this session could attempt (everything for an operator). */
  async listCapabilities(query: ListCapabilitiesQuery = {}): Promise<ListCapabilitiesResponse> {
    return this.request(
      "GET",
      "/v1/capabilities",
      (d) => ListCapabilitiesResponseSchema.parse(d),
      undefined,
      query,
    );
  }

  /** POST /v1/grants: bind a policy to an agent under limits. */
  async createGrant(req: CreateGrantRequest): Promise<CreateGrantResponse> {
    return this.request(
      "POST",
      "/v1/grants",
      (d) => CreateGrantResponseSchema.parse(d),
      CreateGrantRequestSchema.parse(req),
    );
  }

  /** POST /v1/invoke: call a capability. The secret is injected server-side; the result returns redacted. */
  async invoke(req: InvokeRequest): Promise<InvokeResponse> {
    return this.request(
      "POST",
      "/v1/invoke",
      (d) => InvokeResponseSchema.parse(d),
      InvokeRequestSchema.parse(req),
    );
  }

  /** POST /v1/approvals: resolve a pending approval (approve or deny). */
  async resolveApproval(req: ResolveApprovalRequest): Promise<ResolveApprovalResponse> {
    return this.request(
      "POST",
      "/v1/approvals",
      (d) => ResolveApprovalResponseSchema.parse(d),
      ResolveApprovalRequestSchema.parse(req),
    );
  }

  /** GET /v1/audit-events: page the hash-chained audit log. */
  async listAuditEvents(query: ListAuditEventsQuery = {}): Promise<ListAuditEventsResponse> {
    return this.request(
      "GET",
      "/v1/audit-events",
      (d) => ListAuditEventsResponseSchema.parse(d),
      undefined,
      query,
    );
  }

  /** POST /v1/secrets: store a secret. The plaintext is encrypted at rest immediately and never returned. */
  async createSecret(req: CreateSecretRequest): Promise<CreateSecretResponse> {
    return this.request(
      "POST",
      "/v1/secrets",
      (d) => CreateSecretResponseSchema.parse(d),
      CreateSecretRequestSchema.parse(req),
    );
  }

  /** POST /v1/secrets/:id/rotate: rotate a secret to a new version. Returns only the new `SecretRef`. */
  async rotateSecret(secretId: string, req: RotateSecretRequest = {}): Promise<RotateSecretResponse> {
    return this.request(
      "POST",
      `/v1/secrets/${encodeURIComponent(secretId)}/rotate`,
      (d) => RotateSecretResponseSchema.parse(d),
      RotateSecretRequestSchema.parse(req),
    );
  }

  /** POST /v1/devices/enroll: enroll a device into the org. */
  async enrollDevice(req: EnrollDeviceRequest): Promise<EnrollDeviceResponse> {
    return this.request(
      "POST",
      "/v1/devices/enroll",
      (d) => EnrollDeviceResponseSchema.parse(d),
      EnrollDeviceRequestSchema.parse(req),
    );
  }

  /** POST /v1/agents/register: register an agent identity. */
  async registerAgent(req: RegisterAgentRequest): Promise<RegisterAgentResponse> {
    return this.request(
      "POST",
      "/v1/agents/register",
      (d) => RegisterAgentResponseSchema.parse(d),
      RegisterAgentRequestSchema.parse(req),
    );
  }
}
