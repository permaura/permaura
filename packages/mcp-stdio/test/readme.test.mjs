import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const README = readFileSync(new URL("../README.md", import.meta.url), "utf8");

// The README states the proof's bounds as they are: a copy of the gateway's store can answer it too, and the proof and the request are two connections.
test("the README states what the bearer proof does not cover", () => {
  assert.doesNotMatch(README, /Only the gateway that issued the token can answer/, "a copy of the store can answer too");
  assert.match(README, /a copy of its data/);
  assert.match(README, /two connections/);
});
