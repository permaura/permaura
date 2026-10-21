/**
 * Where the bridge takes this agent's token from, in order: `--token`, `--token-file`, `PERMAURA_AGENT_TOKEN`, then the file `PERMAURA_AGENT_TOKEN_FILE` names. The file form keeps the token out of every command line and every MCP client's config: `permaura agent enroll --out <path>` writes a code there, readable only by its owner, and the config holds only the path.
 */
import { lstatSync, readFileSync } from "node:fs";
import { homedir } from "node:os";

/** What the bridge needs to know of a token file before trusting it. */
export interface TokenFileStat {
  mode: number;
  isFile: boolean;
  isSymbolicLink: boolean;
}

export interface TokenSources {
  /** `--token`, if given. */
  flag?: string;
  /** `--token-file`, if given. */
  fileFlag?: string;
  /** The process environment. */
  env: Record<string, string | undefined>;
  /** Reads a file as text; replaced in tests. */
  read?: (path: string) => string;
  /** Describes a path without following a symlink; replaced in tests. */
  stat?: (path: string) => TokenFileStat;
}

export interface ResolvedToken {
  token?: string;
  /** A note for stderr, when where the token came from deserves one. */
  note?: string;
  /** Why the bridge must not start: a token file was named and could not be used. */
  fatal?: string;
}

const realStat = (path: string): TokenFileStat => {
  const s = lstatSync(path);
  return { mode: s.mode, isFile: s.isFile(), isSymbolicLink: s.isSymbolicLink() };
};

/** The agent's token from the first source that has one, with a note when a source was passed over or put the token where other users can read it, and a fatal reason when a named file cannot be used. */
export function resolveAgentToken(sources: TokenSources): ResolvedToken {
  if (sources.flag) {
    return {
      token: sources.flag,
      note: "--token puts this agent's token in the process list, readable by every local user for as long as the bridge runs. Use PERMAURA_AGENT_TOKEN_FILE (or PERMAURA_AGENT_TOKEN) instead.",
    };
  }
  const fromEnv = sources.env.PERMAURA_AGENT_TOKEN;
  if (sources.fileFlag) {
    const read = fromFile(sources.fileFlag, sources);
    const passedOver = fromEnv ? "PERMAURA_AGENT_TOKEN is set too and was ignored: --token-file names this agent's token." : undefined;
    const note = [passedOver, read.note].filter(Boolean).join(" ");
    return note ? { ...read, note } : read;
  }
  if (fromEnv) {
    return sources.env.PERMAURA_AGENT_TOKEN_FILE
      ? { token: fromEnv, note: "PERMAURA_AGENT_TOKEN_FILE is set too and was ignored: PERMAURA_AGENT_TOKEN holds this agent's token." }
      : { token: fromEnv };
  }
  const path = sources.env.PERMAURA_AGENT_TOKEN_FILE;
  return path ? fromFile(path, sources) : {};
}

/** The token in the file at `path` (a leading `~/` being the home directory), checked first. */
function fromFile(path: string, sources: TokenSources): ResolvedToken {
  const resolved = path === "~" || path.startsWith("~/") ? homedir() + path.slice(1) : path;
  const notes: string[] = [];
  try {
    const st = (sources.stat ?? realStat)(resolved);
    if (st.isSymbolicLink || !st.isFile) {
      notes.push(`${resolved} is not a regular file, so where this agent's token comes from can change under it.`);
    } else if ((st.mode & 0o077) !== 0) {
      notes.push(`${resolved} is readable by other users; make it readable by you alone (chmod 600), as permaura agent enroll --out does.`);
    }
  } catch {
    // An unreadable stat leaves the read below to say what is wrong.
  }
  try {
    const token = (sources.read ?? ((p) => readFileSync(p, "utf8")))(resolved).trim();
    if (!token) return { fatal: `${resolved} is empty, so this agent has no token.` };
    return notes.length ? { token, note: notes.join(" ") } : { token };
  } catch (err) {
    return { fatal: `could not read this agent's token from ${resolved} (${err instanceof Error ? err.message : String(err)}).` };
  }
}
