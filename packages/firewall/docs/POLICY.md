# Policy reference

Policies are JSON. Missing sections fall back to conservative defaults (`agenttx init` writes the full default). Arrays such as `programs` and `destinations.allow` **replace** the defaults; objects such as `limits` merge.

```jsonc
{
  "version": 1,
  "cluster": "mainnet-beta",          // mainnet-beta | devnet | testnet | localnet
  "signer": "<agent public key>",     // optional; else the signer object / fee payer

  "programs": [                       // program allowlist
    { "id": "11111111111111111111111111111111", "name": "System Program", "instructions": ["transfer"] },
    { "id": "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "name": "Jupiter",
      "instructions": ["route", "shared_accounts_route", "exact_out_route", "shared_accounts_exact_out_route"] }
    // "instructions": ["*"] allows everything for that program; "disc:<16 hex>" matches an Anchor discriminator
  ],

  "destinations": { "allow": [{ "address": "<wallet or token account>", "label": "treasury" }] },

  "tokens": {                         // token allowlist; SOL is always available
    "USDC": { "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "decimals": 6, "maxPerTx": "100" }
  },

  "limits": {
    "maxSolPerTx": "0.5",
    "maxSolPerDay": "2",              // needs a SpendingLedger
    "maxSlippageBps": 100,
    "maxPriorityFeeLamports": 1000000,
    "rentToleranceLamports": 5000000, // extra SOL a swap may spend on token-account rent
    "maxInstructions": 12
  },

  "authority": { "allowApprove": false, "allowSetAuthority": false, "allowedDelegates": [] },
  "swaps": { "requireOutputToSelf": true },
  "injection": { "mode": "block" },   // "block": high-severity injection blocks; "warn": forces REVIEW
  "simulation": { "required": false } // true: no RPC / failed simulation blocks
}
```

Notes

- Destinations: transfers to the agent's own accounts (its wallet and its associated token accounts) are always fine. Token transfers to an allowlisted *wallet* are accepted when the destination is that wallet's associated token account for the mint.
- Approvals stay blocked unless `authority.allowApprove` is true **and** the delegate is in `allowedDelegates` **and** the amount is not effectively unlimited. The `approve` instruction must also be in the token program's instruction allowlist.
- Default policies allow Jupiter v6 route instructions and the token/system/ATA/compute-budget plumbing a swap needs, nothing else.
