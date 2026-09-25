// Vercel serverless function (Node.js runtime, ESM).
// Read-only: this endpoint only ever calls AgentTxFirewall.inspect() / evaluateIntent().
// It never holds a signer and never sends a transaction — nothing it does can move funds.
import { AgentTxFirewall, JupiterSwapProvider, parseTransactionInput, parseIntent } from "../lib/agenttx-firewall/index.js";

// Simulation is opt-in and, when on, only ever calls read-only Solana RPC methods
// (simulateTransaction / getAccountInfo / getBalance / getLatestBlockhash) against the
// public mainnet endpoint. No signer is ever configured here, so nothing can be sent.
const RPC_URL = "https://api.mainnet-beta.solana.com";

function json(res, status, body) {
  res.status(status).setHeader("content-type", "application/json").end(JSON.stringify(body));
}

export default async function handler(req, res) {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-methods", "POST, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type");
  if (req.method === "OPTIONS") return void res.status(204).end();
  if (req.method !== "POST") return json(res, 405, { error: "Use POST" });

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return json(res, 400, { error: "Request body is not valid JSON" });
    }
  }
  if (!body || typeof body !== "object") return json(res, 400, { error: "Request body must be a JSON object" });

  const { mode, transaction, intent, policy, context, simulate } = body;

  let firewall;
  try {
    firewall = new AgentTxFirewall({
      policy: policy ?? {},
      rpc: simulate ? RPC_URL : undefined,
      // Evaluating a swap intent fetches a real quote + unsigned transaction from Jupiter's
      // public API (jup.ag) so the demo shows the actual build step. This is read-only:
      // nothing here ever signs or sends, and the fetched transaction is fully re-inspected
      // below like any other transaction before a verdict is produced.
      swapProvider: new JupiterSwapProvider(),
    });
  } catch (e) {
    return json(res, 400, { error: `Invalid policy: ${e.message}` });
  }

  const ctx =
    context && (Array.isArray(context.untrusted) ? context.untrusted.length : 0) > 0
      ? { untrusted: context.untrusted, trusted: context.trusted }
      : context?.trusted
        ? { untrusted: [], trusted: context.trusted }
        : undefined;

  try {
    if (mode === "intent") {
      if (!intent) return json(res, 400, { error: 'mode "intent" needs an "intent" field' });
      let parsedIntent;
      try {
        parsedIntent = parseIntent(intent);
      } catch (e) {
        return json(res, 200, { report: null, error: e.message });
      }
      const decision = await firewall.evaluateIntent(parsedIntent, ctx);
      return json(res, 200, { report: decision.report });
    }

    if (!transaction) return json(res, 400, { error: 'mode "transaction" needs a "transaction" field' });
    let wire;
    try {
      wire = parseTransactionInput(transaction);
    } catch (e) {
      return json(res, 200, { report: null, error: `Could not parse transaction: ${e.message}` });
    }
    const report = await firewall.inspect(wire, { context: ctx, simulate: Boolean(simulate) });
    return json(res, 200, { report });
  } catch (e) {
    return json(res, 500, { error: e.message ?? "Internal error" });
  }
}
