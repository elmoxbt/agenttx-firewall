# AgentTx Firewall

**Cloudflare for Solana AI agents.** Open-source TypeScript middleware that sits between an AI agent and its Solana signer.

```
AI AGENT
   |   { "action": "swap", "input": "SOL", "output": "USDC", "amount": "0.2", "maximum": "0.5 SOL" }
   v
AGENTTX FIREWALL
   +-- Intent parser         agents can only name transfer / swap, never build transactions
   +-- Deterministic builder intent -> real transaction (built by us, not by the model)
   +-- Program / instruction / account / amount / destination checks
   +-- Authority + prompt-injection + address-provenance checks
   +-- Simulation            RPC simulate, CPI log scan, balance-delta check
   +-- Security report       ALLOW / REVIEW / BLOCK
   v
SOLANA SIGNER   (only ever sees transactions the firewall approved)
```

The model never gets a generic `sendTransaction`. Everything it asks for is re-derived by deterministic code, and every transaction — even one built by a third-party API like Jupiter — is fully re-inspected before it can be signed.

Zero runtime dependencies. Dev dependencies: `typescript`, `@types/node`.

## Quick start

Requires Node.js 22+.

```bash
npm install
npm test            # typecheck + 36 offline tests
npm run build       # -> dist/
npm run examples    # regenerate the demo files in examples/

# a clean transfer: ALLOW (exit 0)
node dist/cli.js inspect examples/transfer-ok.tx.json --policy examples/agenttx.policy.json

# the attack: unlimited approval requested by a poisoned tool response: BLOCKED (exit 1)
node dist/cli.js inspect examples/malicious-approve.tx.json \
  --policy examples/agenttx.policy.json --context examples/malicious-tool-output.txt

# the same attack arriving as an agent intent
node dist/cli.js intent examples/intent-malicious-approve.json \
  --policy examples/agenttx.policy.json --context examples/malicious-tool-output.txt
```

Install the CLI globally from the folder with `npm link` and call it as `agenttx`.

## Example report

```
AGENTTX SECURITY REPORT

Program: Jupiter
Action: Swap
Input: 0.2 SOL
Expected output: USDC

[PASS] Transaction structure
[PASS] Program allowlist
[PASS] Instruction allowlist
[PASS] Authority escalation
[PASS] Destination allowlist
[PASS] Token allowlist
[PASS] Amount limit
[PASS] Slippage
[PASS] Swap output destination
[PASS] Priority fee
[PASS] Matches declared intent
[PASS] Simulation

RISK: LOW
VERDICT: ALLOW
```

And the injection case:

```
[FAIL] Instruction allowlist — Unexpected approval instruction
[FAIL] Destination allowlist — Destination not allowlisted: <address>
[FAIL] Authority escalation — Authority escalation detected (unlimited spending authority)
[FAIL] Prompt-injection scan — Untrusted content contains wallet-targeted instructions
[FAIL] Destination provenance — Address appears only in untrusted tool output

RISK: CRITICAL
VERDICT: BLOCKED
```

Exit codes: `0` ALLOW, `1` BLOCK, `2` REVIEW, `64` usage/input error. Add `--json` for machine-readable output.

## SDK

```ts
import { AgentTxFirewall, JupiterSwapProvider, KeypairSigner } from "agenttx-firewall";

const signer = KeypairSigner.fromFile("./agent-keypair.json"); // dev only: use a KMS/HSM in production

const firewall = new AgentTxFirewall({
  policy: {
    cluster: "mainnet-beta",
    signer: signer.publicKey,
    destinations: { allow: [{ address: "<treasury>", label: "treasury" }] },
    limits: { maxSolPerTx: "0.5", maxSolPerDay: "2", maxSlippageBps: 100 },
  },
  rpc: "mainnet",
  signer,
  swapProvider: new JupiterSwapProvider({ apiKey: process.env.JUPITER_API_KEY }),
  auditLog: ".agenttx/audit.jsonl",
});

// Tool for the agent: takes an intent, never a transaction.
async function agentTool(intent: unknown, seenContent: string[]) {
  const result = await firewall.execute(intent, { untrusted: seenContent, trusted: userMessage });
  return { verdict: result.report.verdict, reasons: result.report.reasons, signature: result.signature };
}
```

- `firewall.evaluateIntent(intent, ctx)` – build + inspect, no signing.
- `firewall.execute(intent, ctx)` – build → inspect → sign → send. Only `ALLOW` is signed; `REVIEW` and `BLOCK` never are.
- `firewall.inspect(tx, { intent?, context?, simulate? })` – inspect any serialized transaction (legacy or v0).
- `firewall.guard()` – returns a `GuardedSigner` with **no raw `signMessage`**; `signTransaction()` throws `FirewallBlockedError` unless the firewall allows it. Use it to wrap an existing agent framework's signer.
- `firewall.scan(text)` – prompt-injection scan for tool output, web pages, emails.

Pass `context.untrusted` (everything the agent read that did not come from the operator) and `context.trusted` (the operator's own instruction) for the AI-specific checks.

## What is checked

| Check | Blocks when |
|---|---|
| Transaction structure | unparseable, no instructions, too many instructions, **unresolved address lookup tables (fail closed)** |
| Program allowlist | any instruction targets a program not in the policy |
| Instruction allowlist | instruction not allowlisted for its program (names, Anchor names via sha256 discriminator, or `disc:<hex>`) |
| Authority escalation | token `approve`, `set_authority`, `assign`, nonce authority changes, unlimited approvals |
| Destination allowlist | SOL/token recipients, `close_account` targets that are not self-owned or allowlisted |
| Token allowlist | mints outside the policy |
| Amount limit | per-tx SOL/token limits, daily SOL window (ledger), decimals mismatch |
| Slippage / platform fee | Jupiter route slippage above the limit (fee → REVIEW) |
| Swap output destination | swap output not landing in the agent's own token account |
| Priority fee | compute price × units above the limit |
| Matches declared intent | transaction does more than the intent said (extra spend, wrong mint, wrong recipient) |
| Prompt-injection scan | untrusted text contains wallet-targeted instructions |
| Destination provenance | a non-allowlisted address came *only* from untrusted content |
| Simulation | simulation error, Approve/SetAuthority in CPI logs, wallet balance drop above limit |

The injection scanner looks for unlimited-approval requests, authority changes, key/seed-phrase requests, instruction overrides, concealment ("don't tell the user"), drain-funds phrasing, "required first step" demands, hidden Unicode / tag characters, HTML comments and opaque blobs.

## Project layout

```
src/
  firewall.ts        orchestrator (inspect / evaluateIntent / execute / guard)
  checks.ts          all security checks
  builder.ts         intent -> transaction (SOL / SPL transfers, swaps via provider)
  jupiter.ts         Jupiter swap provider (quote + swap, output re-inspected)
  intent/            intent schema + validation
  policy/            policy types, defaults, validation
  guard/injection.ts prompt-injection scanner
  solana/            wire-format parser, instruction decoders, RPC client, constants
  report.ts          verdict/risk + text report
  signer.ts          Signer, KeypairSigner, GuardedSigner
  ledger.ts          rolling spend window
  cli.ts             agenttx CLI
test/                node:test suites (offline, mocked RPC)
examples/            demo transactions, intents, policy, SDK + devnet scripts
policies/            starter policies (devnet, mainnet)
docs/                ARCHITECTURE.md, POLICY.md
```

## Free to develop and test

- **Unit tests** are fully offline (`npm test`).
- **Devnet**: `examples/devnet-transfer.mjs` runs intent → simulate → sign → send on devnet with a faucet-funded keypair.
- **Local validator**: `--rpc localnet` (or `rpc: "http://127.0.0.1:8899"`) with `solana-test-validator`.
- **CI**: `.github/workflows/ci.yml` runs typecheck, tests, build and CLI smoke tests.
- Jupiter only routes on mainnet. Use `--rpc mainnet` in read-only mode (inspect/simulate, no signing) to check real swap transactions for free.

## Status and known limitations

This is an MVP and has not been audited. Read these before trusting it with funds:

- **Live network paths are untested here.** The RPC client and the Jupiter provider were written against the documented APIs but the test suite uses mocks and synthetic transactions. Run devnet and a mainnet read-only simulate first. The Jupiter endpoint default (`lite-api.jup.ag/swap/v1`) is configurable; use `api.jup.ag` with a key for production.
- **Jupiter decoding is best-effort.** Route amounts, slippage and output accounts are decoded from the instruction layout as I know it. Verify against Jupiter's current IDL; if a layout changes the checks fail closed (mismatch → block) or warn.
- **Static analysis sees top-level instructions only.** CPIs are invisible statically; the simulation log scan catches token `Approve`/`SetAuthority` inside CPIs but is not exhaustive.
- **Injection detection is heuristic** (regex rules). Treat it as one layer; the hard guarantees come from intents, allowlists and provenance checks, which do not depend on language understanding.
- Transfers are built as legacy transactions; swaps may be v0 and need an RPC to resolve lookup tables.
- Token-2022 extension instructions are blocked by default; add Token-2022 rules to your policy deliberately.
- Simulation reflects current chain state and can differ at landing time.

## Roadmap ideas

Priority-fee-aware builders, more protocol decoders (Orca, Raydium, Meteora), approval workflows for `REVIEW`, Squads / multisig signer adapters, richer taint tracking across multi-step agent traces, MCP server wrapper, Anchor IDL loading for arbitrary programs.

## License

MIT
