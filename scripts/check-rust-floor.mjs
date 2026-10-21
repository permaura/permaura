#!/usr/bin/env node
// Fail if any crate in the locked dependency graph needs a newer Rust than the workspace's rust-version, the floor README.md gives anyone building from source.
//
// The MSRV-aware resolver only stops `cargo update` from choosing such a crate; a version named in a manifest is taken as written, which is how sysinfo 0.39 (Rust 1.95) sat under a 1.88 promise.
//
// Usage: node scripts/check-rust-floor.mjs [extra `cargo metadata` flags, e.g. --offline]

import { execFileSync } from "node:child_process";

const metadata = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--locked", "--all-features", ...process.argv.slice(2)], {
    encoding: "utf8",
    maxBuffer: 1 << 28,
  }),
);

const parts = (v) => v.split(".").map(Number);
const compare = (a, b) => {
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < 3; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
};

const members = new Set(metadata.workspace_members);
const memberFloors = [...new Set(metadata.packages.filter((p) => members.has(p.id)).map((p) => p.rust_version))];
if (memberFloors.length !== 1 || !memberFloors[0]) {
  console.error(`workspace members do not share one rust-version: ${JSON.stringify(memberFloors)}`);
  process.exit(1);
}
const floor = memberFloors[0];

const resolved = new Set(metadata.resolve.nodes.map((n) => n.id));
const graph = metadata.packages.filter((p) => resolved.has(p.id) && p.rust_version);
const above = graph.filter((p) => compare(p.rust_version, floor) > 0);
const highest = graph.reduce((top, p) => (compare(p.rust_version, top.rust_version) > 0 ? p : top));

if (above.length > 0) {
  console.error(`The workspace promises Rust ${floor}, but the locked graph needs more:`);
  for (const p of above.sort((a, b) => compare(b.rust_version, a.rust_version))) {
    console.error(`  ${p.name} ${p.version} declares rust-version ${p.rust_version}`);
  }
  process.exit(1);
}
console.log(
  `Rust floor ${floor} holds: ${graph.length} of ${resolved.size} locked packages declare a rust-version, the highest is ${highest.rust_version} (${highest.name} ${highest.version}).`,
);
