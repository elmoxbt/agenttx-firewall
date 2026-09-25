import { isAuthorityIntent } from "./intent/intent.js";
import { decimalsForMint, resolveAsset, symbolForMint } from "./policy/policy.js";
import { TOKEN_PROGRAMS, WSOL_MINT } from "./solana/constants.js";
import { anchorDiscriminator } from "./solana/decode.js";
import { scanText } from "./guard/injection.js";
import { shortAddr } from "./util/base58.js";
import { deriveAta } from "./util/pda.js";
import { formatUnits, parseUnits } from "./util/units.js";
export function res(id, name, status, message, details, critical = false) {
    return { id, name, status, message, ...(details?.length ? { details } : {}), ...(critical && status === "fail" ? { critical: true } : {}) };
}
export function buildCheckContext(args) {
    const { policy, self, decoded } = args;
    const mints = new Set([WSOL_MINT, ...Object.values(policy.tokens).map((t) => t.mint)]);
    for (const d of decoded) {
        const p = d.parsed;
        if (p.type === "ata_create")
            mints.add(p.mint);
        if (p.type === "token_transfer" && p.mint)
            mints.add(p.mint);
        if (p.type === "swap_route") {
            if (p.sourceMint)
                mints.add(p.sourceMint);
            if (p.destinationMint)
                mints.add(p.destinationMint);
        }
    }
    const selfTokenAccounts = new Map();
    for (const mint of mints)
        for (const tp of TOKEN_PROGRAMS)
            selfTokenAccounts.set(deriveAta(self, mint, tp), mint);
    return {
        policy,
        self,
        feePayer: args.tx.staticAccountKeys[0],
        signers: args.signers,
        tx: args.tx,
        decoded,
        unresolvedLookups: args.unresolvedLookups,
        intent: args.intent && !isAuthorityIntent(args.intent) ? args.intent : undefined,
        allowed: new Set(policy.destinations.allow.map((d) => d.address)),
        selfTokenAccounts,
        spentInWindow: args.spentInWindow,
    };
}
const parsedOf = (ctx, type) => ctx.decoded.filter((d) => d.parsed.type === type).map((d) => ({ d, p: d.parsed }));
const tokenRuleByMint = (policy, mint) => {
    for (const [symbol, t] of Object.entries(policy.tokens))
        if (t.mint === mint)
            return { ...t, symbol };
    return undefined;
};
export function solOutLamports(ctx) {
    let total = 0n;
    for (const { p } of parsedOf(ctx, "sol_transfer"))
        if (p.from === ctx.self)
            total += p.lamports;
    for (const { p } of parsedOf(ctx, "sol_create_account"))
        if (p.from === ctx.self)
            total += p.lamports;
    return total;
}
const sol = (l) => `${formatUnits(l, 9)} SOL`;
const U64_HALF = (1n << 64n) / 2n;
// ---------------------------------------------------------------------------------------------
export function checkStructure(ctx) {
    const problems = [];
    if (ctx.unresolvedLookups) {
        problems.push("Address lookup tables could not be resolved, so some accounts are hidden (fail closed)");
    }
    for (const d of ctx.decoded) {
        if (d.parsed.type === "malformed")
            problems.push(`Instruction #${d.index}: ${d.parsed.reason}`);
    }
    if (ctx.decoded.length === 0)
        problems.push("Transaction has no instructions");
    if (ctx.decoded.length > ctx.policy.limits.maxInstructions) {
        problems.push(`${ctx.decoded.length} instructions exceeds the limit of ${ctx.policy.limits.maxInstructions}`);
    }
    if (problems.length)
        return res("structure", "Transaction structure", "fail", problems[0], problems);
    const notes = [];
    if (!ctx.signers.includes(ctx.self)) {
        return res("structure", "Transaction structure", "warn", "Agent signer is not a required signer of this transaction", notes);
    }
    return res("structure", "Transaction structure", "pass", `${ctx.decoded.length} instructions decoded`);
}
export function checkPrograms(ctx) {
    const rules = new Map(ctx.policy.programs.map((r) => [r.id, r]));
    const bad = ctx.decoded.filter((d) => !rules.has(d.programId));
    if (bad.length) {
        const uniq = [...new Set(bad.map((d) => `${d.programLabel} (${d.programId})`))];
        return res("program-allowlist", "Program allowlist", "fail", `Program not allowlisted: ${uniq[0]}`, uniq);
    }
    const names = [...new Set(ctx.decoded.map((d) => d.programLabel))];
    return res("program-allowlist", "Program allowlist", "pass", `All programs allowlisted: ${names.join(", ")}`);
}
function instructionAllowed(rules, d) {
    if (rules.includes("*"))
        return true;
    if (rules.includes(d.name))
        return true;
    if (d.discriminator) {
        return rules.some((r) => r === `disc:${d.discriminator}` || (!r.startsWith("disc:") && anchorDiscriminator(r) === d.discriminator));
    }
    return false;
}
export function checkInstructions(ctx) {
    const rules = new Map(ctx.policy.programs.map((r) => [r.id, r.instructions]));
    const bad = [];
    for (const d of ctx.decoded) {
        const allowed = rules.get(d.programId);
        if (!allowed)
            continue; // reported by the program check
        if (!instructionAllowed(allowed, d))
            bad.push(`#${d.index} ${d.programLabel}.${d.name}`);
    }
    if (bad.length)
        return res("instruction-allowlist", "Instruction allowlist", "fail", `Instruction not allowlisted: ${bad[0]}`, bad);
    return res("instruction-allowlist", "Instruction allowlist", "pass", "All instructions allowlisted");
}
export function checkAuthority(ctx) {
    const { authority } = ctx.policy;
    const problems = [];
    const programIds = new Set(ctx.policy.programs.map((p) => p.id));
    for (const { d, p } of parsedOf(ctx, "token_approve")) {
        const unlimited = p.amount >= U64_HALF;
        const amt = unlimited ? "UNLIMITED" : `${p.amount} raw units`;
        if (!authority.allowApprove) {
            problems.push(`#${d.index} Unexpected approval instruction: delegate ${p.delegate} for ${amt}`);
        }
        else if (!authority.allowedDelegates.includes(p.delegate)) {
            problems.push(`#${d.index} Unexpected approval instruction: non-allowlisted delegate ${p.delegate} for ${amt}`);
        }
        else if (unlimited) {
            problems.push(`#${d.index} Unexpected approval instruction: unlimited approval to ${p.delegate}`);
        }
    }
    for (const { d, p } of parsedOf(ctx, "authority_change")) {
        const ok = authority.allowSetAuthority && p.newAuthority !== null && ctx.allowed.has(p.newAuthority);
        if (!ok)
            problems.push(`#${d.index} Authority escalation detected: ${p.kind} authority of ${p.target} → ${p.newAuthority ?? "none"}`);
    }
    for (const { d, p } of parsedOf(ctx, "assign")) {
        if (p.account === ctx.self)
            problems.push(`#${d.index} Authority escalation detected: agent wallet would be assigned to program ${p.owner}`);
        else if (!programIds.has(p.owner))
            problems.push(`#${d.index} Authority escalation detected: account ${p.account} assigned to non-allowlisted program ${p.owner}`);
    }
    for (const { d, p } of parsedOf(ctx, "sol_create_account")) {
        if (p.owner !== "11111111111111111111111111111111" && !programIds.has(p.owner)) {
            problems.push(`#${d.index} Authority escalation detected: account created with non-allowlisted owner program ${p.owner}`);
        }
    }
    if (problems.length) {
        return res("authority", "Authority escalation", "fail", problems[0].replace(/^#\d+ /, ""), problems, true);
    }
    return res("authority", "Authority escalation", "pass", "No approvals, delegations or authority changes");
}
export function checkDestinations(ctx) {
    const bad = [];
    let count = 0;
    const selfOwned = (a) => a === ctx.self || ctx.selfTokenAccounts.has(a);
    const tokenDestOk = (dest, mint) => {
        if (selfOwned(dest) || ctx.allowed.has(dest))
            return true;
        if (mint) {
            for (const owner of ctx.allowed)
                for (const tp of TOKEN_PROGRAMS)
                    if (deriveAta(owner, mint, tp) === dest)
                        return true;
        }
        return false;
    };
    for (const { d, p } of parsedOf(ctx, "sol_transfer")) {
        count++;
        if (!(selfOwned(p.to) || ctx.allowed.has(p.to)))
            bad.push(`#${d.index} SOL transfer to ${p.to} (${sol(p.lamports)}) — destination not allowlisted`);
    }
    for (const { d, p } of parsedOf(ctx, "sol_create_account")) {
        count++;
        if (!(ctx.signers.includes(p.newAccount) || ctx.allowed.has(p.newAccount))) {
            bad.push(`#${d.index} Funding unknown account ${p.newAccount} — destination not allowlisted`);
        }
    }
    for (const { d, p } of parsedOf(ctx, "token_transfer")) {
        count++;
        if (!tokenDestOk(p.destination, p.mint))
            bad.push(`#${d.index} Token transfer to ${p.destination} — destination not allowlisted`);
    }
    for (const { d, p } of parsedOf(ctx, "token_close")) {
        count++;
        if (!(selfOwned(p.destination) || ctx.allowed.has(p.destination))) {
            bad.push(`#${d.index} Closing account ${p.account} sends remaining funds to ${p.destination} — destination not allowlisted`);
        }
    }
    if (bad.length)
        return res("destination", "Destination allowlist", "fail", `Destination not allowlisted`, bad);
    const warns = [];
    for (const { d, p } of parsedOf(ctx, "ata_create")) {
        if (!(p.owner === ctx.self || ctx.allowed.has(p.owner)))
            warns.push(`#${d.index} Creates a token account for non-allowlisted owner ${p.owner} (you pay the rent)`);
    }
    if (warns.length)
        return res("destination", "Destination allowlist", "warn", warns[0].replace(/^#\d+ /, ""), warns);
    return res("destination", "Destination allowlist", "pass", count ? `${count} recipient(s) are self-owned or allowlisted` : "No value transfers");
}
export function checkTokens(ctx) {
    const bad = [];
    const warns = [];
    const known = (mint) => mint === WSOL_MINT || !!tokenRuleByMint(ctx.policy, mint);
    for (const { d, p } of parsedOf(ctx, "token_transfer")) {
        if (!p.mint)
            warns.push(`#${d.index} Unchecked token transfer: mint unknown, amount cannot be verified`);
        else if (!known(p.mint))
            bad.push(`#${d.index} Token ${p.mint} is not in the token allowlist`);
    }
    for (const { d, p } of parsedOf(ctx, "swap_route")) {
        for (const [label, m] of [["input", p.sourceMint], ["output", p.destinationMint]]) {
            if (m && !known(m))
                bad.push(`#${d.index} Swap ${label} token ${m} is not in the token allowlist`);
            if (!m)
                warns.push(`#${d.index} Swap ${label} token could not be determined`);
        }
    }
    if (bad.length)
        return res("token-allowlist", "Token allowlist", "fail", bad[0].replace(/^#\d+ /, ""), bad);
    if (warns.length)
        return res("token-allowlist", "Token allowlist", "warn", warns[0].replace(/^#\d+ /, ""), warns);
    return res("token-allowlist", "Token allowlist", "pass", "All tokens allowlisted");
}
export function checkAmounts(ctx) {
    const { policy } = ctx;
    const bad = [];
    const warns = [];
    const maxSol = parseUnits(policy.limits.maxSolPerTx, 9);
    const out = solOutLamports(ctx);
    if (out > maxSol)
        bad.push(`SOL outflow ${sol(out)} exceeds per-transaction limit ${sol(maxSol)}`);
    if (policy.limits.maxSolPerDay && ctx.spentInWindow !== undefined) {
        const day = parseUnits(policy.limits.maxSolPerDay, 9);
        if (ctx.spentInWindow + out > day)
            bad.push(`Daily SOL limit ${sol(day)} would be exceeded (already spent ${sol(ctx.spentInWindow)})`);
    }
    const tokenLimit = (mint, amount, decimals, where) => {
        if (mint === WSOL_MINT) {
            if (amount > maxSol)
                bad.push(`${where}: ${sol(amount)} exceeds per-transaction limit ${sol(maxSol)}`);
            return;
        }
        const rule = tokenRuleByMint(policy, mint);
        if (!rule)
            return; // token allowlist check reports it
        if (decimals !== undefined && decimals !== rule.decimals) {
            bad.push(`${where}: decimals ${decimals} do not match policy (${rule.decimals}) for ${rule.symbol}`);
            return;
        }
        if (!rule.maxPerTx) {
            warns.push(`${where}: no per-transaction limit configured for ${rule.symbol}`);
            return;
        }
        const max = parseUnits(rule.maxPerTx, rule.decimals);
        if (amount > max)
            bad.push(`${where}: ${formatUnits(amount, rule.decimals)} ${rule.symbol} exceeds limit ${rule.maxPerTx}`);
    };
    for (const { d, p } of parsedOf(ctx, "token_transfer"))
        if (p.mint)
            tokenLimit(p.mint, p.amount, p.decimals, `#${d.index} token transfer`);
    for (const { d, p } of parsedOf(ctx, "swap_route")) {
        const maxIn = p.mode === "exact_in" ? p.amount : p.otherAmount;
        if (p.sourceMint)
            tokenLimit(p.sourceMint, maxIn, undefined, `#${d.index} swap input`);
        else if (out === 0n)
            warns.push(`#${d.index} swap input amount cannot be verified (source token unknown)`);
    }
    if (bad.length)
        return res("amount-limit", "Amount limit", "fail", bad[0], bad);
    if (warns.length)
        return res("amount-limit", "Amount limit", "warn", warns[0], warns);
    return res("amount-limit", "Amount limit", "pass", `SOL outflow ${sol(out)} within limits`);
}
export function checkSwap(ctx) {
    const swaps = parsedOf(ctx, "swap_route");
    if (swaps.length === 0) {
        return [res("slippage", "Slippage", "skip", "No swap in transaction")];
    }
    const results = [];
    const bad = [];
    const warns = [];
    for (const { d, p } of swaps) {
        if (p.slippageBps > ctx.policy.limits.maxSlippageBps) {
            bad.push(`#${d.index} slippage ${p.slippageBps} bps exceeds limit ${ctx.policy.limits.maxSlippageBps} bps`);
        }
        if (p.platformFeeBps > 0)
            warns.push(`#${d.index} route takes a ${p.platformFeeBps} bps platform fee`);
    }
    results.push(bad.length
        ? res("slippage", "Slippage", "fail", bad[0].replace(/^#\d+ /, ""), bad)
        : warns.length
            ? res("slippage", "Slippage", "warn", warns[0].replace(/^#\d+ /, ""), warns)
            : res("slippage", "Slippage", "pass", `Within ${ctx.policy.limits.maxSlippageBps} bps`));
    if (ctx.policy.swaps.requireOutputToSelf) {
        const badOut = [];
        const unverifiable = [];
        for (const { d, p } of swaps) {
            if (!p.destination || !p.destinationMint) {
                unverifiable.push(`#${d.index} output account could not be determined`);
                continue;
            }
            const ok = p.destination === ctx.self ||
                TOKEN_PROGRAMS.some((tp) => deriveAta(ctx.self, p.destinationMint, tp) === p.destination) ||
                ctx.allowed.has(p.destination);
            if (!ok)
                badOut.push(`#${d.index} swap output goes to ${p.destination}, which is not the agent's token account`);
        }
        results.push(badOut.length
            ? res("swap-output", "Swap output destination", "fail", badOut[0].replace(/^#\d+ /, ""), badOut, true)
            : unverifiable.length
                ? res("swap-output", "Swap output destination", "warn", unverifiable[0].replace(/^#\d+ /, ""), unverifiable)
                : res("swap-output", "Swap output destination", "pass", "Swap output lands in the agent's own token account"));
    }
    return results;
}
export function checkPriorityFee(ctx) {
    const price = parsedOf(ctx, "compute_price")[0]?.p.microLamports;
    if (price === undefined)
        return res("priority-fee", "Priority fee", "pass", "No priority fee set");
    const units = BigInt(parsedOf(ctx, "compute_limit")[0]?.p.units ?? 1_400_000);
    const fee = (price * units + 999999n) / 1000000n;
    const max = BigInt(ctx.policy.limits.maxPriorityFeeLamports);
    if (fee > max)
        return res("priority-fee", "Priority fee", "fail", `Priority fee up to ${fee} lamports exceeds limit ${max}`);
    return res("priority-fee", "Priority fee", "pass", `Up to ${fee} lamports`);
}
export function checkIntentMatch(ctx) {
    const intent = ctx.intent;
    if (!intent)
        return res("intent-match", "Matches declared intent", "skip", "No intent supplied");
    const { policy } = ctx;
    const problems = [];
    const solTransfers = parsedOf(ctx, "sol_transfer").filter(({ p }) => p.from === ctx.self);
    const tokenTransfers = parsedOf(ctx, "token_transfer");
    const swaps = parsedOf(ctx, "swap_route");
    const out = solOutLamports(ctx);
    if (intent.action === "transfer") {
        const asset = resolveAsset(policy, intent.asset);
        if (!asset)
            return res("intent-match", "Matches declared intent", "fail", `Asset ${intent.asset} is not allowlisted`);
        const raw = parseUnits(intent.amount, asset.decimals);
        if (swaps.length)
            problems.push("Transaction contains a swap the intent did not ask for");
        if (asset.native) {
            const hits = solTransfers.filter(({ p }) => p.to === intent.to && p.lamports === raw);
            if (hits.length !== 1)
                problems.push(`Expected exactly one transfer of ${intent.amount} SOL to ${intent.to}`);
            if (out !== raw)
                problems.push(`SOL outflow ${sol(out)} differs from intent ${intent.amount} SOL`);
            if (tokenTransfers.length)
                problems.push("Unexpected token transfer");
        }
        else {
            const hits = tokenTransfers.filter(({ p }) => p.mint === asset.mint &&
                p.amount === raw &&
                TOKEN_PROGRAMS.some((tp) => deriveAta(intent.to, asset.mint, tp) === p.destination));
            if (hits.length !== 1 || tokenTransfers.length !== 1) {
                problems.push(`Expected exactly one transfer of ${intent.amount} ${asset.symbol} to ${intent.to}`);
            }
            if (out > 0n)
                problems.push(`Unexpected SOL outflow ${sol(out)}`);
        }
    }
    else if (intent.action === "swap") {
        const inp = resolveAsset(policy, intent.input);
        const outp = resolveAsset(policy, intent.output);
        if (!inp || !outp)
            return res("intent-match", "Matches declared intent", "fail", "Swap asset is not allowlisted");
        const raw = parseUnits(intent.amount, inp.decimals);
        if (swaps.length === 0)
            problems.push("Transaction contains no swap instruction");
        for (const { p } of swaps) {
            const spend = p.mode === "exact_in" ? p.amount : p.otherAmount;
            if (spend > raw)
                problems.push(`Swap spends up to ${formatUnits(spend, inp.decimals)} ${inp.symbol}, more than intended ${intent.amount}`);
            if (p.sourceMint && p.sourceMint !== inp.mint)
                problems.push(`Swap input token ${p.sourceMint} differs from intent (${inp.symbol})`);
            if (p.destinationMint && p.destinationMint !== outp.mint)
                problems.push(`Swap output token ${p.destinationMint} differs from intent (${outp.symbol})`);
            if (intent.slippageBps !== undefined && p.slippageBps > intent.slippageBps) {
                problems.push(`Slippage ${p.slippageBps} bps exceeds intent (${intent.slippageBps} bps)`);
            }
        }
        const allowance = inp.native ? raw + BigInt(policy.limits.rentToleranceLamports) : BigInt(policy.limits.rentToleranceLamports);
        if (out > allowance)
            problems.push(`SOL outflow ${sol(out)} exceeds intent plus rent tolerance`);
        if (tokenTransfers.length)
            problems.push("Unexpected direct token transfer inside a swap");
    }
    if (problems.length)
        return res("intent-match", "Matches declared intent", "fail", problems[0], problems);
    return res("intent-match", "Matches declared intent", "pass", "Transaction does exactly what the intent declared");
}
export function checkInjection(context, policy) {
    const texts = context?.untrusted ?? [];
    if (texts.length === 0) {
        return { check: res("injection", "Prompt-injection scan", "skip", "No untrusted context supplied"), findings: [], addresses: [] };
    }
    const findings = [];
    const addresses = new Set();
    for (const t of texts) {
        const r = scanText(t);
        findings.push(...r.findings);
        r.addresses.forEach((a) => addresses.add(a));
    }
    const high = findings.filter((f) => f.severity === "high");
    const medium = findings.filter((f) => f.severity === "medium");
    const details = findings.map((f) => `[${f.severity}] ${f.description}: "${f.excerpt}"`);
    let check;
    if (high.length) {
        check = res("injection", "Prompt-injection scan", policy.injection.mode === "block" ? "fail" : "warn", `Untrusted content contains wallet-targeted instructions (${high.map((f) => f.rule).join(", ")})`, details, true);
    }
    else if (medium.length) {
        check = res("injection", "Prompt-injection scan", "warn", `Suspicious instructions in untrusted content (${medium.map((f) => f.rule).join(", ")})`, details);
    }
    else {
        check = res("injection", "Prompt-injection scan", "pass", findings.length ? "Only low-severity patterns found" : "No injection patterns found", details);
    }
    return { check, findings, addresses: [...addresses] };
}
/** Counterparty addresses in a decoded transaction that are neither the agent's own nor allowlisted. */
export function outsideAddresses(ctx) {
    const out = new Set();
    const consider = (a) => {
        if (a && a !== ctx.self && !ctx.selfTokenAccounts.has(a) && !ctx.allowed.has(a))
            out.add(a);
    };
    for (const d of ctx.decoded) {
        const p = d.parsed;
        if (p.type === "sol_transfer")
            consider(p.to);
        else if (p.type === "token_transfer")
            consider(p.destination);
        else if (p.type === "token_approve")
            consider(p.delegate);
        else if (p.type === "authority_change")
            consider(p.newAuthority);
        else if (p.type === "token_close")
            consider(p.destination);
        else if (p.type === "assign")
            consider(p.owner);
        else if (p.type === "swap_route")
            consider(p.destination);
    }
    return [...out];
}
/**
 * Taint check: a non-allowlisted address that the agent only learned from untrusted content
 * (and that the operator never mentioned) must never receive funds or authority.
 */
export function checkProvenance(suspects, context, allowed, self) {
    const texts = context?.untrusted ?? [];
    if (texts.length === 0)
        return res("provenance", "Destination provenance", "skip", "No untrusted context supplied");
    const trusted = context?.trusted ?? "";
    const tainted = suspects.filter((a) => a !== self && !allowed.has(a) && texts.some((t) => t.includes(a)) && !trusted.includes(a));
    if (tainted.length) {
        return res("provenance", "Destination provenance", "fail", `Address ${shortAddr(tainted[0])} appears only in untrusted tool output`, tainted.map((a) => `${a} was taken from untrusted content and is not allowlisted`), true);
    }
    return res("provenance", "Destination provenance", "pass", "No untrusted address reached a transfer or approval");
}
// ---------------------------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------------------------
export async function runSimulation(ctx, rpc, wire) {
    if (!rpc) {
        return {
            check: res("simulation", "Simulation", ctx.policy.simulation.required ? "fail" : "skip", "No RPC configured; static checks only"),
            summary: { ran: false },
        };
    }
    try {
        const pre = await rpc.getBalance(ctx.self);
        const sim = await rpc.simulateTransaction(wire, { accounts: [ctx.self] });
        const cpi = new Set();
        const dangerous = new Set();
        for (const line of sim.logs) {
            const m = /^Program (\w+) invoke \[\d+\]/.exec(line);
            if (m)
                cpi.add(m[1]);
            const ix = /Program log: Instruction: (Approve|ApproveChecked|SetAuthority)\b/.exec(line);
            if (ix)
                dangerous.add(ix[1]);
        }
        const post = sim.accounts[0]?.lamports;
        const change = post !== undefined ? post - pre : undefined;
        const summary = {
            ran: true,
            ok: !sim.err,
            unitsConsumed: sim.unitsConsumed,
            solChangeLamports: change?.toString(),
            cpiPrograms: [...cpi],
        };
        if (sim.err) {
            summary.error = JSON.stringify(sim.err);
            return { check: res("simulation", "Simulation", "fail", `Simulation failed: ${summary.error}`, sim.logs.slice(-5)), summary };
        }
        if (dangerous.size && !ctx.policy.authority.allowApprove) {
            return {
                check: res("simulation", "Simulation", "fail", `Execution performs ${[...dangerous].join("/")} (visible in program logs, possibly via CPI)`, [...dangerous], true),
                summary,
            };
        }
        const allowance = parseUnits(ctx.policy.limits.maxSolPerTx, 9) +
            BigInt(ctx.policy.limits.rentToleranceLamports) +
            BigInt(ctx.policy.limits.maxPriorityFeeLamports) +
            5000n * BigInt(ctx.tx.header.numRequiredSignatures);
        if (change !== undefined && -change > allowance) {
            return {
                check: res("simulation", "Simulation", "fail", `Simulated wallet balance drops by ${sol(-change)}, above the allowed ${sol(allowance)}`),
                summary,
            };
        }
        const details = [
            `compute units: ${sim.unitsConsumed ?? "n/a"}`,
            `wallet SOL change: ${change === undefined ? "n/a" : sol(change)}`,
            `programs invoked: ${[...cpi].map(shortAddr).join(", ") || "none"}`,
        ];
        return { check: res("simulation", "Simulation", "pass", "Simulation succeeded", details), summary };
    }
    catch (e) {
        const msg = e.message;
        return {
            check: res("simulation", "Simulation", ctx.policy.simulation.required ? "fail" : "warn", `Simulation could not run: ${msg}`),
            summary: { ran: false, error: msg },
        };
    }
}
export { symbolForMint, decimalsForMint };
//# sourceMappingURL=checks.js.map