/**
 * Shared primitives for the connector signing chain (root → intermediate cert → leaf), kept
 * byte-identical to the Rust verifier in `services/gateway/src/manifest.rs`. Used by the offline CA
 * ceremony tool (`pmconn-ca.ts`), the connector signer (`sign-connector.ts`), and the signing
 * service. If you change a preimage here, change `manifest.rs` in lockstep (the cross-language test
 * `ts_ca_output_verifies_against_pinned_dev_root` guards it).
 */
import { createPrivateKey, createPublicKey, sign as edSign, generateKeyPairSync } from "node:crypto";

/** Ed25519 raw 32-byte key I/O (matching the gateway's raw-key convention, with no PKCS#8/SPKI on the wire). */
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function rawSecretToKeyObject(raw32: Buffer) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw32]), format: "der", type: "pkcs8" });
}
export function rawPubToKeyObject(raw32: Buffer) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw32]), format: "der", type: "spki" });
}
export function pubFromSecretRaw(raw32: Buffer): Buffer {
  const sk = rawSecretToKeyObject(raw32);
  return createPublicKey(sk).export({ type: "spki", format: "der" }).subarray(-32);
}
export function ed25519Sign(raw32Secret: Buffer, message: Buffer): Buffer {
  return edSign(null, message, rawSecretToKeyObject(raw32Secret));
}
export function generateRawKeypair(): { pub: Buffer; sec: Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    pub: publicKey.export({ type: "spki", format: "der" }).subarray(-32),
    sec: privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
  };
}

/** Length-prefixed append: 4-byte big-endian length + bytes. Mirrors `manifest.rs::lp`. */
function lp(parts: Buffer[], field: Buffer | string): void {
  const b = typeof field === "string" ? Buffer.from(field, "utf8") : field;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length, 0);
  parts.push(len, b);
}

/** The preimage the ROOT signs to issue an intermediate certificate. Mirrors `manifest.rs::cert_preimage`. */
export function certPreimage(keyId: string, pubkeyRaw: Buffer, issuedAt: number, expiresAt: number, rootKeyId: string): Buffer {
  const parts: Buffer[] = [Buffer.from("permaura-pmconn/v1/intermediate-cert", "utf8")];
  lp(parts, keyId);
  lp(parts, pubkeyRaw);
  lp(parts, String(issuedAt));
  lp(parts, String(expiresAt));
  lp(parts, rootKeyId);
  return Buffer.concat(parts);
}

export interface IntermediateCert {
  key_id: string;
  pubkey: string;
  issued_at: number;
  expires_at: number;
  root_key_id: string;
  root_sig: string;
}

/** Issue a root-signed intermediate certificate. `rootSecretRaw` is the offline root secret. */
export function issueCert(
  rootSecretRaw: Buffer,
  rootKeyId: string,
  intKeyId: string,
  intPubRaw: Buffer,
  issuedAt: number,
  expiresAt: number,
): IntermediateCert {
  const pre = certPreimage(intKeyId, intPubRaw, issuedAt, expiresAt, rootKeyId);
  return {
    key_id: intKeyId,
    pubkey: intPubRaw.toString("base64"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    root_key_id: rootKeyId,
    root_sig: ed25519Sign(rootSecretRaw, pre).toString("base64"),
  };
}

export interface RevokedManifest {
  id: string;
  up_to_version: number;
}
export interface RevocationList {
  revoked_key_ids: string[];
  revoked_manifests: RevokedManifest[];
  issued_at: number;
  serial: number;
  root_key_id: string;
  root_sig: string;
}

/**
 * The preimage the ROOT signs for a revocation list. Mirrors `manifest.rs::revocation_preimage`: each list goes under its own name and item count, so an item cannot be moved from one list to the other under the same signature.
 */
export function revocationPreimage(serial: number, issuedAt: number, keyIds: string[], mans: RevokedManifest[], rootKeyId: string): Buffer {
  const parts: Buffer[] = [Buffer.from("permaura-pmconn/v2/revocation", "utf8")];
  lp(parts, String(serial));
  lp(parts, String(issuedAt));
  // Sort bytewise (code-unit order) to match Rust `String::cmp`, NOT localeCompare: a locale-order
  // mismatch would make the gateway re-derive a different preimage and reject the revocation (fail
  // open). The id charset is ASCII, so code-unit order equals UTF-8 byte order.
  const byId = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  lp(parts, "revoked_key_ids");
  lp(parts, String(keyIds.length));
  for (const k of [...keyIds].sort(byId)) lp(parts, k);
  lp(parts, "revoked_manifests");
  lp(parts, String(mans.length));
  for (const m of [...mans].sort((a, b) => byId(a.id, b.id))) {
    lp(parts, m.id);
    lp(parts, String(m.up_to_version));
  }
  lp(parts, rootKeyId);
  return Buffer.concat(parts);
}

export function signRevocation(
  rootSecretRaw: Buffer,
  rootKeyId: string,
  serial: number,
  issuedAt: number,
  keyIds: string[],
  mans: RevokedManifest[],
): RevocationList {
  const pre = revocationPreimage(serial, issuedAt, keyIds, mans, rootKeyId);
  return {
    revoked_key_ids: keyIds,
    revoked_manifests: mans,
    issued_at: issuedAt,
    serial,
    root_key_id: rootKeyId,
    root_sig: ed25519Sign(rootSecretRaw, pre).toString("base64"),
  };
}

/**
 * Canonical JSON for the LEAF signature: compact, recursively-sorted keys. Mirrors `manifest.rs::canonicalize`.
 *
 * It throws on anything outside the format both sides print identically: a number that is not a safe integer (JavaScript and serde_json print the rest differently), an object key with a character above U+FFFF (UTF-16 and code-point order differ there), or a lone surrogate. Signing such a manifest would produce a signature the gateway can never verify.
 */
export function canonical(v: unknown, at = "$"): string {
  if (Array.isArray(v)) return "[" + v.map((item, i) => canonical(item, `${at}[${i}]`)).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v as Record<string, unknown>).sort()
      .map((k) => {
        if (/[\uD800-\uDFFF]/.test(k)) throw new Error(`cannot sign ${at}: the key ${JSON.stringify(k)} has a character above U+FFFF or a lone surrogate`);
        return JSON.stringify(k) + ":" + canonical((v as Record<string, unknown>)[k], `${at}.${k}`);
      })
      .join(",") + "}";
  }
  if (typeof v === "number" && !Number.isSafeInteger(v)) throw new Error(`cannot sign ${at}: ${v} is not a safe integer`);
  if (typeof v === "string" && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(v)) throw new Error(`cannot sign ${at}: the string has a lone surrogate`);
  return JSON.stringify(v);
}

/** The bytes a LEAF signature covers: canonical `{manifest, version}`. Mirrors `manifest.rs::canonical_bytes`. */
export function leafMessage(manifest: unknown, version: number): Buffer {
  return Buffer.from(canonical({ manifest, version }), "utf8");
}
