import { readFileSync } from "node:fs";
import { isAddress } from "../util/base58.js";
import {
  ATA_PROGRAM,
  COMPUTE_BUDGET_PROGRAM,
  JUPITER_V6_PROGRAM,
  KNOWN_TOKENS,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  WSOL_MINT,
} from "../solana/constants.js";
import type { Cluster } from "../types.js";
import { parseUnits } from "../util/units.js";

export interface ProgramRule {
  id: string;
  name: string;
  /** Allowed instruction names (snake_case), Anchor names, `disc:<hex>`, or "*" for any. */
  instructions: string[];
}

export interface TokenRule {
  mint: string;
  decimals: number;
  /** Max per transaction in UI units (e.g. "100" USDC). */
  maxPerTx?: string;
}

export interface Policy {
  version: 1;
  cluster: Cluster;
  /** Public key of the agent's signer. Falls back to the signer object / fee payer. */
  signer?: string;
  programs: ProgramRule[];
  destinations: { allow: { address: string; label?: string }[] };
  /** Token allowlist keyed by symbol. SOL is always available. */
  tokens: Record<string, TokenRule>;
  limits: {
    maxSolPerTx: string;
    maxSolPerDay?: string;
    maxSlippageBps: number;
    maxPriorityFeeLamports: number;
    /** Extra SOL a swap may spend on top of the intent amount (token account rent). */
    rentToleranceLamports: number;
    maxInstructions: number;
  };
  authority: { allowApprove: boolean; allowSetAuthority: boolean; allowedDelegates: string[] };
  swaps: { requireOutputToSelf: boolean };
  injection: { mode: "block" | "warn" };
  simulation: { required: boolean };
}

export function defaultPolicy(cluster: Cluster = "mainnet-beta"): Policy {
  const tokens: Record<string, TokenRule> = {};
  for (const t of KNOWN_TOKENS) {
    if (t.symbol !== "SOL" && t.clusters.includes(cluster)) {
      tokens[t.symbol] = { mint: t.mint, decimals: t.decimals, maxPerTx: "100" };
    }
  }
  return {
    version: 1,
    cluster,
    programs: [
      { id: SYSTEM_PROGRAM, name: "System Program", instructions: ["transfer"] },
      {
        id: COMPUTE_BUDGET_PROGRAM,
        name: "Compute Budget",
        instructions: ["set_compute_unit_limit", "set_compute_unit_price"],
      },
      { id: ATA_PROGRAM, name: "Associated Token Account", instructions: ["create", "create_idempotent"] },
      { id: TOKEN_PROGRAM, name: "SPL Token", instructions: ["transfer_checked", "sync_native", "close_account"] },
      {
        id: JUPITER_V6_PROGRAM,
        name: "Jupiter",
        instructions: ["route", "shared_accounts_route", "exact_out_route", "shared_accounts_exact_out_route"],
      },
    ],
    destinations: { allow: [] },
    tokens,
    limits: {
      maxSolPerTx: "0.5",
      maxSolPerDay: "2",
      maxSlippageBps: 100,
      maxPriorityFeeLamports: 1_000_000,
      rentToleranceLamports: 5_000_000,
      maxInstructions: 12,
    },
    authority: { allowApprove: false, allowSetAuthority: false, allowedDelegates: [] },
    swaps: { requireOutputToSelf: true },
    injection: { mode: "block" },
    simulation: { required: false },
  };
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function fail(msg: string): never {
  throw new Error(`Invalid policy: ${msg}`);
}

function addr(v: unknown, where: string): string {
  if (typeof v !== "string" || !isAddress(v)) fail(`${where} must be a valid Solana address`);
  return v;
}

/** Merge a (possibly partial) user policy over the defaults, then validate it. Arrays replace, objects merge. */
export function resolvePolicy(input: unknown = {}): Policy {
  if (!isObj(input)) fail("policy must be a JSON object");
  const cluster = (input.cluster ?? "mainnet-beta") as Cluster;
  if (!["mainnet-beta", "devnet", "testnet", "localnet"].includes(cluster)) fail(`unknown cluster "${String(cluster)}"`);
  const base = defaultPolicy(cluster);
  const merged: Policy = {
    ...base,
    ...(input as Partial<Policy>),
    limits: { ...base.limits, ...(isObj(input.limits) ? input.limits : {}) },
    authority: { ...base.authority, ...(isObj(input.authority) ? input.authority : {}) },
    swaps: { ...base.swaps, ...(isObj(input.swaps) ? input.swaps : {}) },
    injection: { ...base.injection, ...(isObj(input.injection) ? input.injection : {}) },
    simulation: { ...base.simulation, ...(isObj(input.simulation) ? input.simulation : {}) },
    destinations: { allow: isObj(input.destinations) && Array.isArray(input.destinations.allow) ? (input.destinations.allow as Policy["destinations"]["allow"]) : base.destinations.allow },
    tokens: isObj(input.tokens) ? (input.tokens as Policy["tokens"]) : base.tokens,
    programs: Array.isArray(input.programs) ? (input.programs as ProgramRule[]) : base.programs,
    cluster,
    version: 1,
  };
  validatePolicy(merged);
  return merged;
}

export function validatePolicy(p: Policy): void {
  if (p.signer !== undefined) addr(p.signer, "signer");
  for (const [i, r] of p.programs.entries()) {
    addr(r.id, `programs[${i}].id`);
    if (!Array.isArray(r.instructions) || r.instructions.some((x) => typeof x !== "string")) {
      fail(`programs[${i}].instructions must be an array of strings`);
    }
  }
  for (const [i, d] of p.destinations.allow.entries()) addr(d.address, `destinations.allow[${i}].address`);
  for (const [sym, t] of Object.entries(p.tokens)) {
    addr(t.mint, `tokens.${sym}.mint`);
    if (!Number.isInteger(t.decimals) || t.decimals < 0 || t.decimals > 18) fail(`tokens.${sym}.decimals is invalid`);
    if (t.maxPerTx !== undefined) parseUnits(t.maxPerTx, t.decimals);
  }
  parseUnits(p.limits.maxSolPerTx, 9);
  if (p.limits.maxSolPerDay !== undefined) parseUnits(p.limits.maxSolPerDay, 9);
  for (const k of ["maxSlippageBps", "maxPriorityFeeLamports", "rentToleranceLamports", "maxInstructions"] as const) {
    if (!Number.isInteger(p.limits[k]) || p.limits[k] < 0) fail(`limits.${k} must be a non-negative integer`);
  }
  p.authority.allowedDelegates.forEach((a, i) => addr(a, `authority.allowedDelegates[${i}]`));
  if (!["block", "warn"].includes(p.injection.mode)) fail('injection.mode must be "block" or "warn"');
}

export function loadPolicy(path: string): Policy {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`Could not read policy file ${path}: ${(e as Error).message}`);
  }
  return resolvePolicy(raw);
}

export interface ResolvedAsset {
  symbol: string;
  mint: string;
  decimals: number;
  native: boolean;
}

/** Resolve a symbol or mint against the policy allowlist (SOL is always allowed). */
export function resolveAsset(policy: Policy, ref: string): ResolvedAsset | undefined {
  if (ref.toUpperCase() === "SOL" || ref === WSOL_MINT) {
    return { symbol: "SOL", mint: WSOL_MINT, decimals: 9, native: true };
  }
  for (const [symbol, t] of Object.entries(policy.tokens)) {
    if (symbol.toUpperCase() === ref.toUpperCase() || t.mint === ref) {
      return { symbol, mint: t.mint, decimals: t.decimals, native: false };
    }
  }
  return undefined;
}

/** Display-only symbol lookup (policy first, then well-known tokens for the cluster). */
export function symbolForMint(policy: Policy, mint: string): string | undefined {
  if (mint === WSOL_MINT) return "SOL";
  for (const [symbol, t] of Object.entries(policy.tokens)) if (t.mint === mint) return symbol;
  return KNOWN_TOKENS.find((t) => t.mint === mint)?.symbol;
}

export function decimalsForMint(policy: Policy, mint: string): number | undefined {
  if (mint === WSOL_MINT) return 9;
  for (const t of Object.values(policy.tokens)) if (t.mint === mint) return t.decimals;
  return KNOWN_TOKENS.find((t) => t.mint === mint)?.decimals;
}
