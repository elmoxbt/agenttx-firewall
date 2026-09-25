import { readFileSync } from "node:fs";
import { isAddress } from "../util/base58.js";
import { ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, JUPITER_V6_PROGRAM, KNOWN_TOKENS, SYSTEM_PROGRAM, TOKEN_PROGRAM, WSOL_MINT, } from "../solana/constants.js";
import { parseUnits } from "../util/units.js";
export function defaultPolicy(cluster = "mainnet-beta") {
    const tokens = {};
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
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function fail(msg) {
    throw new Error(`Invalid policy: ${msg}`);
}
function addr(v, where) {
    if (typeof v !== "string" || !isAddress(v))
        fail(`${where} must be a valid Solana address`);
    return v;
}
/** Merge a (possibly partial) user policy over the defaults, then validate it. Arrays replace, objects merge. */
export function resolvePolicy(input = {}) {
    if (!isObj(input))
        fail("policy must be a JSON object");
    const cluster = (input.cluster ?? "mainnet-beta");
    if (!["mainnet-beta", "devnet", "testnet", "localnet"].includes(cluster))
        fail(`unknown cluster "${String(cluster)}"`);
    const base = defaultPolicy(cluster);
    const merged = {
        ...base,
        ...input,
        limits: { ...base.limits, ...(isObj(input.limits) ? input.limits : {}) },
        authority: { ...base.authority, ...(isObj(input.authority) ? input.authority : {}) },
        swaps: { ...base.swaps, ...(isObj(input.swaps) ? input.swaps : {}) },
        injection: { ...base.injection, ...(isObj(input.injection) ? input.injection : {}) },
        simulation: { ...base.simulation, ...(isObj(input.simulation) ? input.simulation : {}) },
        destinations: { allow: isObj(input.destinations) && Array.isArray(input.destinations.allow) ? input.destinations.allow : base.destinations.allow },
        tokens: isObj(input.tokens) ? input.tokens : base.tokens,
        programs: Array.isArray(input.programs) ? input.programs : base.programs,
        cluster,
        version: 1,
    };
    validatePolicy(merged);
    return merged;
}
export function validatePolicy(p) {
    if (p.signer !== undefined)
        addr(p.signer, "signer");
    for (const [i, r] of p.programs.entries()) {
        addr(r.id, `programs[${i}].id`);
        if (!Array.isArray(r.instructions) || r.instructions.some((x) => typeof x !== "string")) {
            fail(`programs[${i}].instructions must be an array of strings`);
        }
    }
    for (const [i, d] of p.destinations.allow.entries())
        addr(d.address, `destinations.allow[${i}].address`);
    for (const [sym, t] of Object.entries(p.tokens)) {
        addr(t.mint, `tokens.${sym}.mint`);
        if (!Number.isInteger(t.decimals) || t.decimals < 0 || t.decimals > 18)
            fail(`tokens.${sym}.decimals is invalid`);
        if (t.maxPerTx !== undefined)
            parseUnits(t.maxPerTx, t.decimals);
    }
    parseUnits(p.limits.maxSolPerTx, 9);
    if (p.limits.maxSolPerDay !== undefined)
        parseUnits(p.limits.maxSolPerDay, 9);
    for (const k of ["maxSlippageBps", "maxPriorityFeeLamports", "rentToleranceLamports", "maxInstructions"]) {
        if (!Number.isInteger(p.limits[k]) || p.limits[k] < 0)
            fail(`limits.${k} must be a non-negative integer`);
    }
    p.authority.allowedDelegates.forEach((a, i) => addr(a, `authority.allowedDelegates[${i}]`));
    if (!["block", "warn"].includes(p.injection.mode))
        fail('injection.mode must be "block" or "warn"');
}
export function loadPolicy(path) {
    let raw;
    try {
        raw = JSON.parse(readFileSync(path, "utf8"));
    }
    catch (e) {
        throw new Error(`Could not read policy file ${path}: ${e.message}`);
    }
    return resolvePolicy(raw);
}
/** Resolve a symbol or mint against the policy allowlist (SOL is always allowed). */
export function resolveAsset(policy, ref) {
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
export function symbolForMint(policy, mint) {
    if (mint === WSOL_MINT)
        return "SOL";
    for (const [symbol, t] of Object.entries(policy.tokens))
        if (t.mint === mint)
            return symbol;
    return KNOWN_TOKENS.find((t) => t.mint === mint)?.symbol;
}
export function decimalsForMint(policy, mint) {
    if (mint === WSOL_MINT)
        return 9;
    for (const t of Object.values(policy.tokens))
        if (t.mint === mint)
            return t.decimals;
    return KNOWN_TOKENS.find((t) => t.mint === mint)?.decimals;
}
//# sourceMappingURL=policy.js.map