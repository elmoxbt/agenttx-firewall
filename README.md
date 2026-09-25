# AgentTx Firewall

A monorepo: the firewall SDK/CLI, and a live web demo of it.

```
agenttx/
  packages/
    firewall/     the real thing — TypeScript SDK, CLI, checks, tests, docs
  apps/
    demo/         a thin read-only web UI deployed on Vercel (free tier)
  scripts/
    sync-demo-lib.mjs   rebuilds packages/firewall and refreshes apps/demo's copy of it
```

**[packages/firewall](packages/firewall/README.md)** is the project: intent-based transaction building, program/instruction/destination/amount allowlists, authority-escalation and prompt-injection detection, simulation, a CLI, and a full offline test suite. This is what you'd publish, embed in an agent framework, or extend with new checks.

**[apps/demo](apps/demo/README.md)** is a two-pane web page — paste a transaction or an agent intent, see the security report render live. It has no logic of its own: it imports a compiled snapshot of `packages/firewall`, kept in sync by `scripts/sync-demo-lib.mjs`. It's a way to show the firewall working without asking anyone to clone a repo.

## Getting started

```bash
npm install                # installs both workspaces at once
npm run build               # builds packages/firewall
npm test                    # runs packages/firewall's test suite
npm run sync-demo           # rebuilds the firewall and refreshes apps/demo/lib
npm run test:demo           # smoke-tests the demo's serverless function (no network needed)
```

Then, to actually deploy the demo:
```bash
cd apps/demo
vercel --prod
```
See [apps/demo/README.md](apps/demo/README.md) for the free-tier deploy walkthrough.

## Why one repo

The demo has no independent existence — it only shows what the firewall does. Keeping them together means one `git push`, one CI run, and a scripted sync step (`npm run sync-demo`) instead of manually copying compiled files between two repos and hoping you remembered to.

## Workflow when you change the firewall

1. Edit `packages/firewall/src/**`.
2. `npm test` (from the root, or `-w agenttx-firewall`) to confirm nothing broke.
3. `npm run sync-demo` to rebuild and refresh `apps/demo/lib/agenttx-firewall`.
4. `npm run test:demo` to confirm the demo's API still behaves as expected.
5. Commit — `git status` will show the refreshed `apps/demo/lib` files alongside your source change, so they land in the same commit.
6. Push. Vercel redeploys the demo automatically if it's connected to this repo (see the demo README for one-time setup); otherwise redeploy manually with `vercel --prod`.

CI (`.github/workflows/ci.yml`) runs steps 2–4 on every push and fails if `apps/demo/lib` is out of sync with `packages/firewall/src` — so a forgotten `sync-demo` gets caught before merge, not after deploy.
