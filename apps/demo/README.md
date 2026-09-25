# AgentTx Firewall — live demo

A read-only web inspector for [AgentTx Firewall](../../packages/firewall). Paste a Solana transaction or an agent intent, optionally paste some "untrusted tool output," and watch the same checks the CLI runs — allowlists, spending limits, authority-escalation detection, prompt-injection scanning — render live.

**This deploys for $0 on Vercel's free Hobby tier.** No credit card, no custom domain needed, no paid add-ons. The one serverless function only ever calls `firewall.inspect()` / `firewall.evaluateIntent()`: it never holds a signer and never sends a transaction, so nothing here can move funds — including when evaluating a swap intent, which fetches a real quote + unsigned transaction from Jupiter's public API purely to show the build step, and the RPC-simulation toggle, which only runs read-only `simulateTransaction` calls.

## What's in this folder

```
public/           static frontend (no build step, no framework)
  index.html
  style.css
  app.js
  samples.js      example transactions/intents, generated from packages/firewall/examples
api/
  inspect.js      the one serverless function — POST { transaction | intent, policy?, context?, simulate? }
lib/
  agenttx-firewall/   compiled JS snapshot of packages/firewall, refreshed by ../../scripts/sync-demo-lib.mjs
test/
  smoke.mjs       offline test of api/inspect.js's logic (see `npm run test:demo` at the repo root)
vercel.json       10s timeout on the function; everything else is Vercel's zero-config defaults
```

`public/` is served as static files and `api/` as a Node.js serverless function automatically — that's Vercel's default behavior for a directory with no framework detected, so there's no build command to configure. `lib/agenttx-firewall` is deliberately a plain, checked-in copy rather than a workspace dependency, so this deployment has no monorepo-specific module resolution to get right.

## Deploy (free, ~2 minutes)

**Option A — via GitHub (recommended):**
1. Push this monorepo to GitHub.
2. Go to https://vercel.com → **Add New → Project** → import the repo.
3. Framework preset: leave as **Other** (auto-detected). **Root Directory: set this to `apps/demo`** — that's the one monorepo-specific setting Vercel needs.
4. Click **Deploy**. No environment variables are required.
5. To get automatic redeploys on push, leave the GitHub integration's default trigger on `main` as-is.

**Option B — via CLI, no GitHub needed:**
```bash
npm i -g vercel      # free
cd apps/demo
vercel               # follow the prompts; first deploy creates the project
vercel --prod        # promote to your production URL
```

Either way you get a `*.vercel.app` URL on the Hobby plan at no cost.

## Run it locally first (optional, also free)

```bash
npm i -g vercel
cd apps/demo
vercel dev
```
This runs the static site and the `/api/inspect` function together on `localhost:3000`, exactly as Vercel would run them in production.

## Updating the bundled library

After changing anything under `../../packages/firewall/src`, run from the repo root:
```bash
npm run sync-demo     # rebuilds packages/firewall, refreshes apps/demo/lib/agenttx-firewall
npm run test:demo     # confirms the demo's handler still behaves correctly
```
Commit the result — `apps/demo/lib` changes alongside your source change in the same commit. CI fails the build if you forget this step (see the root `.github/workflows/ci.yml`).

To refresh the sample transactions shown in the UI: rerun `npm run examples` in `packages/firewall/`, then regenerate `public/samples.js` from the files in `packages/firewall/examples/`.

## Notes and limits

- **Simulation toggle**: when checked, the API calls the public `api.mainnet-beta.solana.com` RPC to run `simulateTransaction` (read-only). That endpoint is free but shared and can rate-limit under load — if simulation fails, uncheck the toggle and you'll still get every static check.
- **"Intent: swap" sample**: this is the one path that makes a live outbound call (to Jupiter's public quote/swap API) to fetch a real route. It's read-only, but it can fail if Jupiter rate-limits the shared endpoint or is briefly unavailable — that will show up as a `BLOCK` with a "Transaction build" reason rather than a crash. The offline smoke test (`npm run test:demo`) deliberately doesn't assert `ALLOW` for this case, since it can't reach the network in every environment; verify it manually with the sample button after a real deploy.
- **Vercel Hobby limits** (as of writing): serverless functions get a generous free monthly invocation quota, more than enough for a demo page. If you expect real traffic, check current limits at vercel.com/pricing before relying on this beyond a demo.
- This has not been tested against a live Vercel deployment from the environment it was built in (no outbound network access there). The handler logic was verified directly with mocked request/response objects — see `test/smoke.mjs` — covering every sample except the live Jupiter call. Test that one manually after your first deploy.
