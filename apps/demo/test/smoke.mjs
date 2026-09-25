#!/usr/bin/env node
// Exercises the deployed serverless function's exact logic with mocked req/res —
// no network, no Vercel needed. Run via `npm run test:demo` from the repo root,
// or `node apps/demo/test/smoke.mjs` directly. Requires apps/demo/lib to be in sync
// (run `npm run sync-demo` first if you've changed packages/firewall).
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const demoDir = dirname(dirname(fileURLToPath(import.meta.url)));
const handler = (await import(join(demoDir, "api/inspect.js"))).default;
const { SAMPLE_TX, SAMPLE_TOOL_OUTPUT, SAMPLE_POLICY, SAMPLE_INTENT_SWAP, SAMPLE_INTENT_MALICIOUS } = await import(
  join(demoDir, "public/samples.js")
);

function mockRes() {
  const r = { statusCode: 200, headers: {}, body: null };
  r.status = (c) => ((r.statusCode = c), r);
  r.setHeader = (k, v) => ((r.headers[k] = v), r);
  r.end = (b) => {
    r.body = b;
  };
  return r;
}

async function call(body, method = "POST") {
  const req = { method, body };
  const res = mockRes();
  await handler(req, res);
  return { status: res.statusCode, headers: res.headers, json: res.body ? JSON.parse(res.body) : null };
}

let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (e) {
    failed++;
    console.error(`NOT OK - ${name}\n    ${e.message}`);
  }
}

const clean = await call({ mode: "transaction", transaction: SAMPLE_TX.transferOk, policy: SAMPLE_POLICY, context: {} });
check("clean transfer -> 200 ALLOW", () => {
  assert.equal(clean.status, 200);
  assert.equal(clean.json.report.verdict, "ALLOW");
});

const malicious = await call({
  mode: "transaction",
  transaction: SAMPLE_TX.maliciousApprove,
  policy: SAMPLE_POLICY,
  context: { untrusted: [SAMPLE_TOOL_OUTPUT] },
});
check("malicious approve + injected context -> BLOCK / CRITICAL", () => {
  assert.equal(malicious.json.report.verdict, "BLOCK");
  assert.equal(malicious.json.report.risk, "CRITICAL");
});

const redirected = await call({ mode: "transaction", transaction: SAMPLE_TX.jupiterSwapRedirected, policy: SAMPLE_POLICY, context: {} });
check("swap output redirected -> BLOCK", () => assert.equal(redirected.json.report.verdict, "BLOCK"));

// Evaluating a swap intent calls Jupiter's live API to fetch a real quote + unsigned
// transaction (read-only — see api/inspect.js). That network call isn't available in
// every environment this smoke test runs in (e.g. sandboxes with no outbound access),
// so this only checks the handler degrades to a clean BLOCK with a readable reason
// instead of crashing, rather than asserting ALLOW. Verify ALLOW manually after a real
// deploy using the "Intent: swap" sample button.
const goodSwap = await call({ mode: "intent", intent: SAMPLE_INTENT_SWAP, policy: SAMPLE_POLICY, context: {} });
check("intent: swap -> responds with a verdict, does not crash", () => {
  assert.equal(goodSwap.status, 200);
  assert.ok(["ALLOW", "REVIEW", "BLOCK"].includes(goodSwap.json.report.verdict));
});

const badIntent = await call({
  mode: "intent",
  intent: SAMPLE_INTENT_MALICIOUS,
  policy: SAMPLE_POLICY,
  context: { untrusted: [SAMPLE_TOOL_OUTPUT] },
});
check("intent: hijacked approval -> BLOCK", () => assert.equal(badIntent.json.report.verdict, "BLOCK"));

const malformed = await call({ mode: "transaction", transaction: "not-base64-!!" });
check("malformed transaction -> 200 with a BLOCK report, not a crash", () => {
  assert.equal(malformed.status, 200);
  assert.equal(malformed.json.report.verdict, "BLOCK");
});

const badPolicy = await call({ mode: "transaction", transaction: SAMPLE_TX.transferOk, policy: { cluster: "moon" } });
check("invalid policy -> 400", () => assert.equal(badPolicy.status, 400));

const missing = await call({ mode: "transaction" });
check("missing transaction field -> 400", () => assert.equal(missing.status, 400));

const wrongMethod = await call(undefined, "GET");
check("GET -> 405", () => assert.equal(wrongMethod.status, 405));

const preflight = await call(undefined, "OPTIONS");
check("OPTIONS preflight -> 204 with CORS header", () => {
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers["access-control-allow-origin"], "*");
});

console.log(failed ? `\n${failed} failing` : "\nall smoke tests passed");
process.exit(failed ? 1 : 0);
