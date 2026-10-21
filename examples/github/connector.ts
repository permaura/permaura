/**
 * Permaura example connector: GitHub.
 *
 * Demonstrates a guarded GitHub workflow where an agent can read a repo, create a branch, open a pull request, and comment, but cannot merge, force-push, delete the repo, or touch repo secrets. It is an illustrative sketch against the SDK's `defineConnector`: the gateway does not load this file, and whoever calls `invoke` supplies the token.
 *
 * Capability ids are `github.<action>`, e.g. `github.pull_requests.create`. Risk tiers drive default policy behavior (see ../../docs/policy-language.md). This file imports from `@permaura/sdk`, which the real SDK provides; here it reads as idiomatic, type-correct TypeScript you could lift into a project.
 */

import { defineConnector, redact } from "@permaura/sdk";
import { z } from "zod";

// A thin, illustrative GitHub client. In a real connector this wraps Octokit; here it documents the surface each capability needs. The `token` is the injected secret and never leaves these functions.
interface GitHubClient {
  getRepo(args: { owner: string; repo: string }, token: string): Promise<unknown>;
  listPullRequests(args: { owner: string; repo: string; state: string }, token: string): Promise<unknown>;
  createBranch(args: { owner: string; repo: string; branch: string; fromRef: string }, token: string): Promise<unknown>;
  createPullRequest(
    args: { owner: string; repo: string; title: string; head: string; base: string; body?: string },
    token: string,
  ): Promise<unknown>;
  commentOnPullRequest(args: { owner: string; repo: string; number: number; body: string }, token: string): Promise<unknown>;
}

declare const github: GitHubClient;

// ---------------------------------------------------------------------------
// Input schemas: the validation boundary between the untrusted agent and the
// upstream call. They run BEFORE execute, so malformed input never touches the
// secret. Strict shapes reject anything unexpected.
// ---------------------------------------------------------------------------

const RepoRef = z.object({
  owner: z.string().min(1).max(100),
  repo: z.string().min(1).max(100),
});

const RepoReadSchema = RepoRef;

const ListPullRequestsSchema = RepoRef.extend({
  state: z.enum(["open", "closed", "all"]).default("open"),
});

const CreateBranchSchema = RepoRef.extend({
  // Branch names are constrained to avoid ref-injection surprises.
  branch: z.string().min(1).max(255).regex(/^[A-Za-z0-9._\/-]+$/),
  fromRef: z.string().min(1).max(255).default("main"),
});

const CreatePullRequestSchema = RepoRef.extend({
  title: z.string().min(1).max(256),
  head: z.string().min(1).max(255),
  base: z.string().min(1).max(255).default("main"),
  body: z.string().max(65_536).optional(),
});

const CommentSchema = RepoRef.extend({
  number: z.number().int().positive(),
  body: z.string().min(1).max(65_536),
});

// ---------------------------------------------------------------------------
// The connector. Capability ids become github.<id>. Risk tiers: read/list are
// low–medium, creating a branch/PR is high, commenting is medium. There is no
// merge, force-push, delete, or secrets.write capability here: those simply do
// not exist on this connector, so an injection that asks for them has nothing
// to call (the safest possible deny).
// ---------------------------------------------------------------------------

export const githubConnector = defineConnector({
  id: "github",
  capabilities: [
    {
      id: "repo.read",
      risk: "low",
      inputSchema: RepoReadSchema,
      execute: async ({ input, secret }) => {
        const repo = await github.getRepo(input, secret);
        // Strip anything token-shaped that a repo payload might carry in webhooks/keys sub-objects.
        return redact(repo, { fields: ["token", "key", "deploy_key", "private_key"] });
      },
    },
    {
      id: "pull_requests.list",
      risk: "low",
      inputSchema: ListPullRequestsSchema,
      execute: async ({ input, secret }) => {
        const prs = await github.listPullRequests(input, secret);
        return redact(prs, { fields: ["token"] });
      },
    },
    {
      id: "branches.create",
      risk: "high",
      inputSchema: CreateBranchSchema,
      execute: async ({ input, secret }) => {
        return github.createBranch(input, secret);
      },
    },
    {
      id: "pull_requests.create",
      // Opening a PR is a write to the repo's history of intent; high-risk so a grant must explicitly allow it.
      risk: "high",
      inputSchema: CreatePullRequestSchema,
      execute: async ({ input, secret, context }) => {
        const pr = await github.createPullRequest(input, secret);
        // context carries session/principal/reason; useful for connectors that vary by environment. Never used to bypass policy: policy already ran.
        void context;
        return pr;
      },
    },
    {
      id: "pull_requests.comment",
      risk: "medium",
      inputSchema: CommentSchema,
      execute: async ({ input, secret }) => {
        return github.commentOnPullRequest(input, secret);
      },
    },
  ],
});

export default githubConnector;
