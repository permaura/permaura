#!/usr/bin/env -S npx tsx
/**
 * Connector signing CA ceremony tool: OFFLINE ONLY.
 *
 * The ROOT key is the cold anchor pinned into the gateway binary; it signs nothing but intermediate
 * certificates. Run this on an air-gapped/cold machine. Secrets are read from env, never written to
 * disk by this tool and never committed.
 *
 *   # 1. Generate the root (once). Pin the pubkey into services/gateway/src/manifest.rs ROOT_PUBKEYS;
 *   #    store the secret cold (HSM / paper / offline vault).
 *   npx tsx scripts/pmconn-ca.ts gen-root
 *
 *   # 2. Generate an intermediate keypair. Its secret goes to the signing service (KMS in prod).
 *   npx tsx scripts/pmconn-ca.ts gen-intermediate
 *
 *   # 3. Issue a root-signed cert for that intermediate (short-lived).
 *   PMCONN_ROOT_SECRET_B64=<root secret> \
 *     npx tsx scripts/pmconn-ca.ts issue-cert --root-key-id pmconn-root-2026a \
 *       --int-key-id pmconn-int-2026a --int-pub <int pub b64> --days 90 > int-cert.json
 *
 *   # 4. Sign a revocation list (root-signed; safe to publish anywhere).
 *   PMCONN_ROOT_SECRET_B64=<root secret> \
 *     npx tsx scripts/pmconn-ca.ts sign-revocation --root-key-id pmconn-root-2026a --serial 3 \
 *       --revoke-key pmconn-int-2025x --revoke-manifest evil:999 > revocation.json
 */
import { generateRawKeypair, issueCert, signRevocation, type RevokedManifest } from "./pmconn-lib";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function argAll(name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < process.argv.length; i++) if (process.argv[i] === `--${name}`) out.push(process.argv[i + 1]);
  return out;
}
function rootSecret(): Buffer {
  const b64 = process.env.PMCONN_ROOT_SECRET_B64;
  if (!b64) {
    console.error("PMCONN_ROOT_SECRET_B64 (base64 of the raw 32-byte root secret) is required and must be provided OFFLINE.");
    process.exit(1);
  }
  return Buffer.from(b64, "base64");
}

const cmd = process.argv[2];

if (cmd === "gen-root" || cmd === "gen-intermediate") {
  const { pub, sec } = generateRawKeypair();
  const which = cmd === "gen-root" ? "ROOT" : "INTERMEDIATE";
  console.error(`${which} keypair generated.`);
  console.log("pubkey_b64:", pub.toString("base64"));
  console.error(`secret_b64 (keep OFFLINE${which === "ROOT" ? " and COLD" : " on the signing service / KMS"}; never commit):`);
  console.error("  secret_b64:", sec.toString("base64"));
} else if (cmd === "issue-cert") {
  const rootKeyId = arg("root-key-id");
  const intKeyId = arg("int-key-id");
  const intPub = arg("int-pub");
  const days = Number.parseInt(arg("days") ?? "90", 10);
  if (!rootKeyId || !intKeyId || !intPub) {
    console.error("issue-cert needs --root-key-id, --int-key-id, --int-pub [--days 90]");
    process.exit(1);
  }
  const now = Number.parseInt(arg("now") ?? String(Date.now()), 10); // --now for deterministic fixtures
  const cert = issueCert(rootSecret(), rootKeyId, intKeyId, Buffer.from(intPub, "base64"), now, now + days * 86_400_000);
  process.stdout.write(JSON.stringify(cert, null, 2) + "\n");
} else if (cmd === "sign-revocation") {
  const rootKeyId = arg("root-key-id");
  const serial = Number.parseInt(arg("serial") ?? "", 10);
  if (!rootKeyId || !Number.isInteger(serial)) {
    console.error("sign-revocation needs --root-key-id --serial N [--revoke-key ID ...] [--revoke-manifest id:version ...]");
    process.exit(1);
  }
  const keyIds = argAll("revoke-key").filter(Boolean);
  const mans: RevokedManifest[] = argAll("revoke-manifest").filter(Boolean).map((s) => {
    const [id, v] = s.split(":");
    return { id, up_to_version: Number.parseInt(v ?? "0", 10) };
  });
  const now = Number.parseInt(arg("now") ?? String(Date.now()), 10);
  process.stdout.write(JSON.stringify(signRevocation(rootSecret(), rootKeyId, serial, now, keyIds, mans), null, 2) + "\n");
} else {
  console.error("Usage: pmconn-ca.ts <gen-root | gen-intermediate | issue-cert | sign-revocation> [flags]");
  process.exit(1);
}
