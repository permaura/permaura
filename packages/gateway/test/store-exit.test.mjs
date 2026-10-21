import { test } from "node:test";
import assert from "node:assert/strict";

import * as lib from "../bin/lib.mjs";

// A start may wait 20 s for another process to let the store go, and then boot.
test("the launcher waits for health longer than a start waits for the store", () => {
  assert.ok(Number.isInteger(lib.HEALTH_WAIT_SECS), "HEALTH_WAIT_SECS is exported");
  assert.ok(lib.HEALTH_WAIT_SECS >= 35, `waits ${lib.HEALTH_WAIT_SECS} s`);
});

test("a gateway exit that names a store problem is explained rather than shown as a bare code", () => {
  assert.equal(typeof lib.exitExplanation, "function");
  assert.match(lib.exitExplanation(73), /holds this home's store/);
  assert.match(lib.exitExplanation(74), /gateway\.db\.auditkey/);
  assert.match(lib.exitExplanation(74), /permaura audit rekey --yes/);
  assert.equal(lib.exitExplanation(0), null);
  assert.equal(lib.exitExplanation(1), null);
});
