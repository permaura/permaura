import process from "node:process";
import type { Readable, Writable } from "node:stream";
import { deserializeMessage, serializeMessage, STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/sdk/shared/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

/**
 * The most bytes one JSON-RPC line may hold before the bridge discards it. The SDK's own default (10 MiB),
 * well above the gateway's 2 MiB body ceiling on `/mcp`, so a frame the gateway would accept is never cut here.
 */
export const DEFAULT_MAX_MESSAGE_BYTES = STDIO_DEFAULT_MAX_BUFFER_SIZE;

/** Environment variable that overrides {@link DEFAULT_MAX_MESSAGE_BYTES}. */
export const MAX_MESSAGE_BYTES_ENV = "PERMAURA_MCP_MAX_MESSAGE_BYTES";

export interface BoundedStdioOptions {
  /** Longest JSON-RPC line accepted, in bytes. Defaults to {@link DEFAULT_MAX_MESSAGE_BYTES}. */
  maxMessageBytes?: number;
  /** Where a discarded message is reported. Defaults to one line on stderr. */
  log?: (line: string) => void;
}

const NEWLINE = 0x0a;

/**
 * The SDK's stdio server transport with one behavioural change: a line longer than the limit is discarded and
 * reported, and the bridge keeps serving. The SDK's transport closes itself instead, which for an agent host
 * means its MCP server is gone until something restarts it.
 *
 * Only the sender that spawned this process can reach its stdin, so an oversized line is that host's own
 * doing; dropping the line and staying up is the useful response, and the gateway's body limit still bounds
 * everything forwarded.
 */
export class BoundedStdioServerTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  private readonly maxMessageBytes: number;
  private readonly log: (line: string) => void;
  private started = false;
  /** Chunks of the current, not yet newline-terminated line, joined only once the newline arrives so a slow line costs one copy, not one per chunk. */
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  /** True while the rest of an oversized line is being skipped up to its newline. */
  private discarding = false;
  private discarded = 0;

  constructor(
    private readonly stdin: Readable = process.stdin,
    private readonly stdout: Writable = process.stdout,
    options: BoundedStdioOptions = {},
  ) {
    const max = options.maxMessageBytes;
    this.maxMessageBytes = Number.isInteger(max) && (max as number) > 0 ? (max as number) : DEFAULT_MAX_MESSAGE_BYTES;
    this.log = options.log ?? ((line) => void process.stderr.write(`${line}\n`));
  }

  private readonly ondata = (chunk: Buffer): void => {
    this.ingest(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  };

  private readonly onstreamerror = (error: Error): void => {
    this.onerror?.(error);
  };

  private ingest(chunk: Buffer): void {
    while (chunk.length > 0) {
      const nl = chunk.indexOf(NEWLINE);
      if (this.discarding) {
        if (nl === -1) {
          this.discarded += chunk.length;
          return;
        }
        this.discarded += nl + 1;
        this.finishDiscard();
        chunk = chunk.subarray(nl + 1);
        continue;
      }
      const lineBytes = nl === -1 ? chunk.length : nl;
      if (this.pendingBytes + lineBytes > this.maxMessageBytes) {
        this.discarded = this.pendingBytes + (nl === -1 ? chunk.length : nl + 1);
        this.pending = [];
        this.pendingBytes = 0;
        if (nl === -1) {
          this.discarding = true;
          return;
        }
        this.finishDiscard();
        chunk = chunk.subarray(nl + 1);
        continue;
      }
      if (nl === -1) {
        this.pending.push(Buffer.from(chunk));
        this.pendingBytes += chunk.length;
        return;
      }
      const line = Buffer.concat([...this.pending, chunk.subarray(0, nl)]).toString("utf8").replace(/\r$/, "");
      this.pending = [];
      this.pendingBytes = 0;
      this.deliver(line);
      chunk = chunk.subarray(nl + 1);
    }
  }

  private finishDiscard(): void {
    this.discarding = false;
    this.log(
      `[permaura-mcp] discarded a ${this.discarded}-byte message: the limit is ${this.maxMessageBytes} bytes (${MAX_MESSAGE_BYTES_ENV}); the bridge keeps running`,
    );
    this.discarded = 0;
  }

  private deliver(line: string): void {
    try {
      this.onmessage?.(deserializeMessage(line));
    } catch (error) {
      this.onerror?.(error instanceof Error ? error : new Error(String(error)));
    }
  }

  async start(): Promise<void> {
    if (this.started) {
      throw new Error("BoundedStdioServerTransport already started; Server.connect() calls start() itself");
    }
    this.started = true;
    this.stdin.on("data", this.ondata);
    this.stdin.on("error", this.onstreamerror);
  }

  async close(): Promise<void> {
    this.stdin.off("data", this.ondata);
    this.stdin.off("error", this.onstreamerror);
    if (this.stdin.listenerCount("data") === 0) {
      this.stdin.pause();
    }
    this.pending = [];
    this.pendingBytes = 0;
    this.discarding = false;
    this.onclose?.();
  }

  send(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve) => {
      if (this.stdout.write(serializeMessage(message))) {
        resolve();
      } else {
        this.stdout.once("drain", resolve);
      }
    });
  }
}

/** Parse the byte limit from the environment: a positive integer, else the default (with a note on stderr for a value that is set but unusable). */
export function maxMessageBytesFromEnv(env: NodeJS.ProcessEnv = process.env, warn: (line: string) => void = (l) => void process.stderr.write(`${l}\n`)): number {
  const raw = env[MAX_MESSAGE_BYTES_ENV];
  if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_MESSAGE_BYTES;
  const n = Number(raw);
  if (Number.isInteger(n) && n > 0) return n;
  warn(`[permaura-mcp] ${MAX_MESSAGE_BYTES_ENV}=${JSON.stringify(raw)} is not a positive integer; using ${DEFAULT_MAX_MESSAGE_BYTES}`);
  return DEFAULT_MAX_MESSAGE_BYTES;
}
