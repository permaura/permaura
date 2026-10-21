#!/usr/bin/env -S npx tsx
/**
 * Prove a stored copy of a signing secret is the right one, without printing it.
 *
 * The moment a key moves into a password manager is the moment it is most likely to be lost: a copy
 * that was truncated, whitespace-mangled or taken from the wrong file looks identical to a good one
 * until the day you need it, and by then the original is gone. This derives the public half from
 * whatever you pasted back and compares it to a key the repository already pins, so the check is
 * against a known-good value rather than against your own memory of it.
 *
 * The secret comes from the environment, never from argv, because argv is visible in `ps` to every
 * process on the machine.
 *
 *   PMCONN_SECRET_B64="$(pbpaste)" npx tsx scripts/pmconn-check-secret.ts pmconn-root-2026a
 *
 * Prints the derived public key, which is public, and never the secret. Exits 0 on a match.
 */
import { readFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";

const MANIFEST = new URL("../services/gateway/src/manifest.rs", import.meta.url);

/** Every key id the gateway pins, root and leaf, read from the Rust source so the two cannot drift. */
function pinned(): Map<string, string> {
  const src = readFileSync(MANIFEST, "utf8");
  const out = new Map<string, string>();
  for (const name of ["ROOT_PUBKEYS", "PINNED_PUBKEYS"]) {
    const block = src.match(new RegExp(`const ${name}:[^=]*=\\s*&\\[([\\s\\S]*?)\\];`));
    if (!block) continue;
    for (const [, id, b64] of block[1].matchAll(/\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)/g)) out.set(id, b64);
  }
  return out;
}

/** The public half of a raw 32-byte Ed25519 seed, via the PKCS8 wrapper node's crypto expects. */
function publicFromSeed(seed: Buffer): string {
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  // The raw key is the last 32 bytes of the SPKI encoding.
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

const wanted = process.argv[2];
const raw = process.env.PMCONN_SECRET_B64;
if (!wanted || !raw) {
  console.error("usage: PMCONN_SECRET_B64=<secret> pmconn-check-secret.ts <key-id>");
  console.error("       the secret comes from the environment so it stays out of ps and shell history");
  process.exit(2);
}

const keys = pinned();
const expected = keys.get(wanted);
if (!expected) {
  console.error(`FAIL: '${wanted}' is not pinned. Pinned: ${[...keys.keys()].join(", ")}`);
  process.exit(1);
}

// Trim, because a paste out of a password manager very often carries a newline or a space.
const seed = Buffer.from(raw.trim(), "base64");
if (seed.length !== 32) {
  console.error(`FAIL: decoded to ${seed.length} bytes, not 32. A truncated or mangled copy.`);
  process.exit(1);
}

const derived = publicFromSeed(seed);
const ok = derived === expected;
console.log(`key id   : ${wanted}`);
console.log(`expected : ${expected}`);
console.log(`derived  : ${derived}`);
console.log(`match    : ${ok ? "YES, this secret is the one pinned in the gateway" : "NO, this is a different key"}`);
process.exit(ok ? 0 : 1);
