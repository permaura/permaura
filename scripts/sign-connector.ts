#!/usr/bin/env -S npx tsx
/**
 * Connector-manifest signer. Produces an install envelope the gateway's POST /v1/connectors/install
 * accepts. Two modes:
 *
 *   # v1 (flat): leaf signature verified directly against a pinned leaf key. The dev/legacy path.
 *   PMCONN_SIGNING_KEY_B64=<leaf secret b64> \
 *     npx tsx scripts/sign-connector.ts <manifest.json> [--version N] [--key-id pmconn-dev] > out.pmconn
 *
 *   # v2 (chained): leaf signed by an INTERMEDIATE whose root-signed cert is attached. Production.
 *   PMCONN_SIGNING_KEY_B64=<intermediate secret b64> \
 *     npx tsx scripts/sign-connector.ts <manifest.json> --version N --cert int-cert.json > out.pmconn
 *
 * The ROOT secret must never live on a network service; the intermediate secret lives on the signing
 * service (or KMS). This CLI is for local/dev signing; the signing service replicates its behaviour.
 */
import { readFileSync } from "node:fs";
import { ed25519Sign, generateRawKeypair, leafMessage, type IntermediateCert } from "./pmconn-lib";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function main(): void {
  if (process.argv.includes("--keygen")) {
    const { pub, sec } = generateRawKeypair();
    console.error("Leaf/dev keypair (pin the pubkey; keep the secret offline):");
    console.log("  pubkey_b64:", pub.toString("base64"));
    console.error("  secret_b64:", sec.toString("base64"));
    return;
  }
  const file = process.argv.slice(2).find((a) => !a.startsWith("--"));
  if (!file) {
    console.error("Usage: sign-connector.ts <manifest.json> [--version N] [--key-id id] [--cert cert.json] | --keygen");
    process.exit(1);
  }
  const version = process.argv.includes("--version") ? Number.parseInt(arg("version") ?? "", 10) : 1;
  if (!Number.isInteger(version) || version < 1) {
    console.error("--version must be a positive integer");
    process.exit(1);
  }
  const secretB64 = process.env.PMCONN_SIGNING_KEY_B64;
  if (!secretB64) {
    console.error("PMCONN_SIGNING_KEY_B64 (base64 of the raw 32-byte signing secret) is not set.");
    process.exit(1);
  }
  const manifest = JSON.parse(readFileSync(file, "utf8"));
  const signature = ed25519Sign(Buffer.from(secretB64, "base64"), leafMessage(manifest, version)).toString("base64");

  const certPath = arg("cert");
  if (certPath) {
    // v2 chained: the key_id is taken from the cert; the signing secret must be the intermediate's.
    const cert = JSON.parse(readFileSync(certPath, "utf8")) as IntermediateCert;
    process.stdout.write(
      JSON.stringify({ manifest, version, signature, key_id: cert.key_id, cert, envelope_version: 2 }, null, 2) + "\n",
    );
    return;
  }
  // v1 flat.
  const keyId = arg("key-id") ?? "pmconn-dev";
  process.stdout.write(JSON.stringify({ manifest, version, signature, key_id: keyId }, null, 2) + "\n");
}

main();
