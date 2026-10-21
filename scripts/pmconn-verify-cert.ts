#!/usr/bin/env -S npx tsx
/**
 * Verify an intermediate certificate against the root the gateway actually pins.
 *
 * The ceremony tool mints certificates offline; this is the other half, and the half that was
 * missing. It reads `ROOT_PUBKEYS` out of `services/gateway/src/manifest.rs` rather than carrying its
 * own copy, so a certificate that verifies here is a certificate a release binary will accept, and a
 * pin edited in one place cannot quietly disagree with a check made in another.
 *
 * Takes no secret and prints no secret, so it is safe to run anywhere, including on the offline
 * machine straight after `issue-cert` and before the certificate is trusted enough to deploy.
 *
 *   npx tsx scripts/pmconn-verify-cert.ts int-cert.json
 *   npx tsx scripts/pmconn-ca.ts issue-cert ... | npx tsx scripts/pmconn-verify-cert.ts -
 *
 * Exits 0 when the signature verifies, 1 when it does not. The validity window is reported but does
 * not fail the check: a certificate can be correctly signed and not yet deployed, or correctly signed
 * and expired, and both are worth seeing rather than being collapsed into one refusal.
 */
import { readFileSync } from "node:fs";
import { createPublicKey, verify as edVerify } from "node:crypto";
import { certPreimage } from "./pmconn-lib";

const MANIFEST = new URL("../services/gateway/src/manifest.rs", import.meta.url);

/** The production roots the gateway pins, read from the Rust source so the two cannot drift. */
function pinnedRoots(): Map<string, Buffer> {
  const src = readFileSync(MANIFEST, "utf8");
  const block = src.match(/const ROOT_PUBKEYS:[^=]*=\s*&\[([\s\S]*?)\];/);
  if (!block) throw new Error("could not find ROOT_PUBKEYS in manifest.rs");
  const out = new Map<string, Buffer>();
  for (const [, id, b64] of block[1].matchAll(/\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)/g)) {
    const raw = Buffer.from(b64, "base64");
    if (raw.length !== 32) throw new Error(`pinned root '${id}' is ${raw.length} bytes, not 32`);
    out.set(id, raw);
  }
  if (out.size === 0) throw new Error("ROOT_PUBKEYS is empty");
  return out;
}

/** Wrap a raw 32-byte Ed25519 public key in the SPKI DER that node's crypto wants. */
function spki(raw: Buffer) {
  return createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]),
    format: "der",
    type: "spki",
  });
}

const arg = process.argv[2];
if (!arg) {
  console.error("usage: pmconn-verify-cert.ts <cert.json | ->");
  process.exit(1);
}
const cert = JSON.parse(readFileSync(arg === "-" ? 0 : arg, "utf8"));

const roots = pinnedRoots();
const root = roots.get(cert.root_key_id);
if (!root) {
  console.error(`FAIL: '${cert.root_key_id}' is not pinned. Pinned: ${[...roots.keys()].join(", ")}`);
  process.exit(1);
}

const pre = certPreimage(
  cert.key_id,
  Buffer.from(cert.pubkey, "base64"),
  cert.issued_at,
  cert.expires_at,
  cert.root_key_id,
);
const ok = edVerify(null, pre, spki(root), Buffer.from(cert.root_sig, "base64"));

const now = Date.now();
const days = (cert.expires_at - now) / 86_400_000;
console.log(`intermediate : ${cert.key_id}`);
console.log(`pubkey       : ${cert.pubkey}`);
console.log(`signed by    : ${cert.root_key_id} (pinned in manifest.rs)`);
console.log(`issued       : ${new Date(cert.issued_at).toISOString()}`);
console.log(`expires      : ${new Date(cert.expires_at).toISOString()}`);
console.log(`life         : ${((cert.expires_at - cert.issued_at) / 86_400_000).toFixed(0)} days`);
console.log(
  `window       : ${now < cert.issued_at ? "NOT YET VALID" : days < 0 ? "EXPIRED" : `valid, ${days.toFixed(0)} days left`}`,
);
console.log(`signature    : ${ok ? "VALID" : "INVALID"}`);
process.exit(ok ? 0 : 1);
