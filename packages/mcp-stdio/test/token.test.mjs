import { test } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";

import { resolveAgentToken } from "../dist/index.js";

// The bridge can take its token from a file, so neither an MCP client's config nor any command line has to hold it.
test("the agent's token comes from the flag, the variable, then the file, in that order", () => {
  const read = (p) => {
    if (p === "/run/agent.token") return "ENRL-FROM-THE-FILE\n";
    if (p === `${homedir()}/.permaura/claude.token`) return "ENRL-FROM-HOME";
    if (p === "/run/empty.token") return "  \n";
    throw new Error("ENOENT: no such file");
  };
  assert.deepEqual(resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/agent.token" }, read }), { token: "ENRL-FROM-THE-FILE" });
  assert.deepEqual(resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "~/.permaura/claude.token" }, read }), { token: "ENRL-FROM-HOME" });
  assert.deepEqual(resolveAgentToken({ fileFlag: "/run/agent.token", env: {}, read }), { token: "ENRL-FROM-THE-FILE" });
  const both = resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN: "from-env", PERMAURA_AGENT_TOKEN_FILE: "/run/agent.token" }, read });
  assert.equal(both.token, "from-env");
  assert.match(both.note, /PERMAURA_AGENT_TOKEN_FILE is set too/, "the variable that was passed over is named");
  const flagged = resolveAgentToken({ flag: "from-flag", env: { PERMAURA_AGENT_TOKEN: "from-env" }, read });
  assert.equal(flagged.token, "from-flag");
  assert.match(flagged.note, /process list/, "a token on the command line is warned about");
  assert.deepEqual(resolveAgentToken({ env: {}, read }), {});
  assert.equal(resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/empty.token" }, read }).token, undefined);
  const missing = resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/missing.token" }, read });
  assert.equal(missing.token, undefined);
  assert.match(missing.fatal, /could not read/);
});

// An explicit --token-file is not overridden by an inherited variable, a file others can read or that is not a regular file is warned about, and a named file that cannot be read is fatal rather than a tokenless bridge.
test("a token file is checked, an explicit one wins, and an unreadable one is fatal", () => {
  const read = (p) => (p === "/run/agent.token" ? "ENRL-FILE" : (() => { throw new Error("ENOENT"); })());
  const tight = () => ({ mode: 0o100600, isFile: true, isSymbolicLink: false });
  const explicit = resolveAgentToken({ fileFlag: "/run/agent.token", env: { PERMAURA_AGENT_TOKEN: "inherited" }, read, stat: tight });
  assert.equal(explicit.token, "ENRL-FILE", "--token-file names this agent's token");
  assert.match(explicit.note, /PERMAURA_AGENT_TOKEN is set too/);

  const loose = resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/agent.token" }, read, stat: () => ({ mode: 0o100644, isFile: true, isSymbolicLink: false }) });
  assert.equal(loose.token, "ENRL-FILE");
  assert.match(loose.note, /readable by other users/);

  const linked = resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/agent.token" }, read, stat: () => ({ mode: 0o120777, isFile: false, isSymbolicLink: true }) });
  assert.match(linked.note, /not a regular file/);

  const missing = resolveAgentToken({ env: { PERMAURA_AGENT_TOKEN_FILE: "/run/missing.token" }, read, stat: tight });
  assert.equal(missing.token, undefined);
  assert.ok(missing.fatal, "a named file that cannot be read stops the bridge");
});
