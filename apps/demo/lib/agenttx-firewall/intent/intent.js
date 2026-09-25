import { isAddress } from "../util/base58.js";
import { parseUnits } from "../util/units.js";
export const AUTHORITY_ACTIONS = new Set([
    "approve",
    "approve_checked",
    "delegate",
    "set_authority",
    "set_owner",
    "change_owner",
    "transfer_ownership",
    "assign",
    "close_account",
    "increase_allowance",
]);
export const SUPPORTED_ACTIONS = ["transfer", "swap"];
export class IntentError extends Error {
}
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function str(o, key, required = true) {
    const v = o[key];
    if (v === undefined || v === null) {
        if (required)
            throw new IntentError(`Missing field "${key}"`);
        return undefined;
    }
    if (typeof v === "number")
        return String(v);
    if (typeof v !== "string")
        throw new IntentError(`Field "${key}" must be a string`);
    return v.trim();
}
/** Split "0.5 SOL" into value and optional asset. */
export function splitAmount(s) {
    const m = /^(\d+(?:\.\d+)?)\s*([A-Za-z0-9]+)?$/.exec(s.trim());
    if (!m)
        throw new IntentError(`Invalid amount "${s}" (expected e.g. "0.5" or "0.5 SOL")`);
    return { value: m[1], asset: m[2] };
}
const cmp = (a, b) => {
    const x = parseUnits(a, 18);
    const y = parseUnits(b, 18);
    return x < y ? -1 : x > y ? 1 : 0;
};
/** Validate untrusted agent output into an Intent. Throws IntentError on anything unexpected. */
export function parseIntent(input) {
    if (typeof input === "string") {
        try {
            input = JSON.parse(input);
        }
        catch {
            throw new IntentError("Intent is not valid JSON");
        }
    }
    if (!isObj(input))
        throw new IntentError("Intent must be a JSON object");
    const action = String(str(input, "action")).toLowerCase();
    if (AUTHORITY_ACTIONS.has(action)) {
        return {
            action,
            authority: true,
            spender: str(input, "spender", false) ?? str(input, "delegate", false) ?? str(input, "to", false) ?? str(input, "address", false),
            asset: str(input, "asset", false) ?? str(input, "token", false),
            amount: str(input, "amount", false) ?? str(input, "maximum", false),
        };
    }
    if (action === "transfer") {
        const asset = str(input, "asset");
        const to = str(input, "to");
        if (!isAddress(to))
            throw new IntentError(`"to" is not a valid Solana address`);
        const a = splitAmount(str(input, "amount"));
        if (a.asset && a.asset.toUpperCase() !== asset.toUpperCase()) {
            throw new IntentError(`Amount unit "${a.asset}" does not match asset "${asset}"`);
        }
        return { action, asset, to, amount: a.value };
    }
    if (action === "swap") {
        const inp = str(input, "input");
        const out = str(input, "output");
        if (inp.toUpperCase() === out.toUpperCase())
            throw new IntentError("Swap input and output are the same asset");
        const amt = str(input, "amount", false);
        const max = str(input, "maximum", false);
        if (!amt && !max)
            throw new IntentError('Swap needs "amount" and/or "maximum"');
        const parts = [amt, max].map((v) => (v ? splitAmount(v) : undefined));
        for (const p of parts) {
            if (p?.asset && p.asset.toUpperCase() !== inp.toUpperCase()) {
                throw new IntentError(`Amount unit "${p.asset}" does not match swap input "${inp}"`);
            }
        }
        const value = parts[0]?.value ?? parts[1].value;
        const maximum = parts[1]?.value;
        if (maximum && cmp(value, maximum) > 0)
            throw new IntentError("Swap amount exceeds the declared maximum");
        let slippageBps;
        if (input.slippageBps !== undefined) {
            slippageBps = Number(input.slippageBps);
            if (!Number.isInteger(slippageBps) || slippageBps < 0 || slippageBps > 10_000) {
                throw new IntentError("slippageBps must be an integer between 0 and 10000");
            }
        }
        return { action, input: inp, output: out, amount: value, maximum, slippageBps };
    }
    throw new IntentError(`Unsupported action "${action}". The firewall only builds: ${SUPPORTED_ACTIONS.join(", ")}. ` +
        `Agents cannot submit arbitrary transactions.`);
}
export const isAuthorityIntent = (i) => "authority" in i;
//# sourceMappingURL=intent.js.map