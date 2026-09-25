# Architecture

## Trust model

| Component | Trusted? |
|---|---|
| Operator's policy file and instruction | yes |
| The LLM / agent | **no** — it may be compromised by prompt injection |
| Tool output, web pages, emails the agent read | **no** |
| Third-party transaction builders (e.g. Jupiter API) | **no** — output is re-inspected |
| The firewall's own builder and checks | yes |
| RPC | partially — used for blockhash, lookup tables and simulation; a malicious RPC can lie, so pin your own |

## Pipeline

```
evaluateIntent(intent, ctx)
  1. parseIntent          strict schema; unknown actions rejected; authority actions (approve,
                          set_authority, ...) are recognised only so they can be blocked with a reason
  2. precheck             asset allowlist, amount limits, destination allowlist, injection scan,
                          address provenance  (blocked intents never reach the builder or the RPC)
  3. build                transfers: compiled locally; swaps: provider output treated as untrusted
  4. inspect(tx)          the same pipeline used for raw transactions
  5. report               ALLOW / REVIEW / BLOCK + RISK

inspect(tx)
  parse wire format (legacy + v0) -> resolve lookup tables via RPC (or fail closed)
  -> decode instructions (System, Token, Token-2022 base set, ATA, Compute Budget, Memo, Jupiter v6)
  -> checks -> simulation (only if static checks passed) -> report
```

Verdict rules: any failed check → `BLOCK`; else any warning → `REVIEW`; else `ALLOW`. A failed critical check (authority escalation, swap output redirect, injection, provenance, CPI approval) raises risk to `CRITICAL`.

## Why intents

A generic `sendTransaction` tool gives the model authority over arbitrary instruction sequences. The intent interface shrinks the model's power to a handful of typed fields. Even a fully hijacked agent can only ask for "transfer X to an allowlisted address" or "swap A for B up to N" — and can never ask for an approval, an ownership change or an unknown program.

## Address provenance (AI-specific)

The agent's context is split into `trusted` (the operator's instruction) and `untrusted` (everything else). If a non-allowlisted address in the intent or transaction appears in untrusted text and not in trusted text, the transaction is blocked: the address was injected, not chosen by the user.

## Adding a protocol

1. Add its program id to `src/solana/constants.ts`.
2. Add a decoder in `src/solana/decode.ts` producing a `Parsed` variant (or use the generic Anchor path and list instruction names in the policy — discriminators are computed from names).
3. Extend `checks.ts` if the protocol has amounts, mints or destinations that must be verified.
4. Add tests with synthetic transactions in `test/`.
