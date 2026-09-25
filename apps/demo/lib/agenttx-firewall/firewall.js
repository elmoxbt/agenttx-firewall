import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { buildSwap, buildTransfer, BuildError } from "./builder.js";
import { buildCheckContext, checkAmounts, checkAuthority, checkDestinations, checkInjection, checkInstructions, checkIntentMatch, checkPriorityFee, checkPrograms, checkProvenance, checkStructure, checkSwap, checkTokens, outsideAddresses, res, runSimulation, } from "./checks.js";
import { isAuthorityIntent, parseIntent, IntentError } from "./intent/intent.js";
import { scanText } from "./guard/injection.js";
import { resolveAsset, resolvePolicy } from "./policy/policy.js";
import { assembleReport, buildSummary, summarizeInstructions } from "./report.js";
import { HttpRpc } from "./solana/rpc.js";
import { decodeAll } from "./solana/decode.js";
import { applyLookups, hasLookups, parseLookupTableAddresses, parseTransaction, requiredSigners, resolveInstructions, } from "./solana/transaction.js";
import { GuardedSigner, signWire } from "./signer.js";
import { fromBase64 } from "./util/bytes.js";
import { parseUnits } from "./util/units.js";
const DAY_MS = 24 * 60 * 60 * 1000;
const emptySummary = (action) => ({
    programs: ["(none)"],
    action,
    solOut: "0 SOL",
    solOutLamports: "0",
    signers: [],
    instructionCount: 0,
});
export class AgentTxFirewall {
    policy;
    rpc;
    signer;
    swapProvider;
    ledger;
    auditLog;
    constructor(opts = {}) {
        this.policy = resolvePolicy(opts.policy ?? {});
        this.rpc = typeof opts.rpc === "string" ? new HttpRpc(opts.rpc) : opts.rpc;
        this.signer = opts.signer;
        this.swapProvider = opts.swapProvider;
        this.ledger = opts.ledger;
        this.auditLog = opts.auditLog;
    }
    /** Scan text the agent has read (tool output, web pages, emails) for wallet-targeted injection. */
    scan(text) {
        return scanText(text);
    }
    /** Wrap a signer so an agent can only obtain signatures through this firewall. */
    guard(signer = this.signer, opts = {}) {
        if (!signer)
            throw new Error("guard() needs a signer");
        return new GuardedSigner(signer, this, opts);
    }
    selfKey(override) {
        return override ?? this.policy.signer ?? this.signer?.publicKey;
    }
    audit(report, intent) {
        if (!this.auditLog)
            return;
        const entry = {
            timestamp: report.timestamp,
            verdict: report.verdict,
            risk: report.risk,
            action: report.summary.action,
            reasons: report.reasons,
            intent,
        };
        try {
            if (typeof this.auditLog === "string") {
                mkdirSync(dirname(this.auditLog), { recursive: true });
                appendFileSync(this.auditLog, `${JSON.stringify(entry)}\n`);
            }
            else
                this.auditLog(entry);
        }
        catch {
            /* auditing must never break the decision path */
        }
    }
    blocked(checks, action, extra = {}, intent) {
        const report = assembleReport({ checks, summary: { ...emptySummary(action), ...extra }, instructions: [] });
        this.audit(report, intent);
        return report;
    }
    // -------------------------------------------------------------------------------------------
    // Transaction inspection
    // -------------------------------------------------------------------------------------------
    async inspect(input, opts = {}) {
        let wire;
        let tx;
        try {
            wire = typeof input === "string" ? fromBase64(input) : input;
            tx = parseTransaction(wire);
        }
        catch (e) {
            return this.blocked([res("structure", "Transaction structure", "fail", `Unparseable transaction: ${e.message}`)], "Unknown");
        }
        const signers = requiredSigners(tx);
        const self = this.selfKey(opts.self) ?? tx.staticAccountKeys[0];
        let loaded;
        let unresolved = false;
        if (hasLookups(tx)) {
            if (!this.rpc)
                unresolved = true;
            else {
                try {
                    const tables = new Map();
                    for (const l of tx.addressTableLookups) {
                        const info = await this.rpc.getAccountInfo(l.accountKey);
                        if (!info)
                            throw new Error(`lookup table ${l.accountKey} not found`);
                        tables.set(l.accountKey, parseLookupTableAddresses(info.data));
                    }
                    loaded = applyLookups(tx, tables);
                }
                catch {
                    unresolved = true;
                }
            }
        }
        let decoded;
        try {
            decoded = decodeAll(resolveInstructions(tx, loaded));
        }
        catch (e) {
            return this.blocked([res("structure", "Transaction structure", "fail", `Cannot decode instructions: ${e.message}`)], "Unknown");
        }
        const spentInWindow = this.ledger && this.policy.limits.maxSolPerDay ? this.ledger.spentSince(DAY_MS) : undefined;
        const ctx = buildCheckContext({ policy: this.policy, self, tx, signers, decoded, unresolvedLookups: unresolved, intent: opts.intent, spentInWindow });
        const checks = [
            checkStructure(ctx),
            checkPrograms(ctx),
            checkInstructions(ctx),
            checkAuthority(ctx),
            checkDestinations(ctx),
            checkTokens(ctx),
            checkAmounts(ctx),
            ...checkSwap(ctx),
            checkPriorityFee(ctx),
            checkIntentMatch(ctx),
        ];
        const inj = checkInjection(opts.context, this.policy);
        checks.push(inj.check);
        const suspects = outsideAddresses(ctx);
        if (opts.intent)
            suspects.push(...intentAddresses(opts.intent));
        checks.push(checkProvenance(suspects, opts.context, ctx.allowed, self));
        const staticFailed = checks.some((c) => c.status === "fail");
        let simulation;
        if ((opts.simulate ?? Boolean(this.rpc)) && !staticFailed) {
            const r = await runSimulation(ctx, this.rpc, wire);
            checks.push(r.check);
            simulation = r.summary;
        }
        else if (staticFailed) {
            checks.push(res("simulation", "Simulation", "skip", "Skipped because static checks failed"));
        }
        else {
            checks.push(res("simulation", "Simulation", this.policy.simulation.required ? "fail" : "skip", this.rpc ? "Simulation disabled" : "No RPC configured (pass --rpc to simulate)"));
        }
        const report = assembleReport({
            checks,
            summary: buildSummary(ctx),
            instructions: summarizeInstructions(decoded),
            injection: inj.findings,
            simulation,
        });
        this.audit(report, opts.intent);
        return report;
    }
    // -------------------------------------------------------------------------------------------
    // Intent flow: the agent never builds transactions, it only names what it wants.
    // -------------------------------------------------------------------------------------------
    async evaluateIntent(input, context) {
        let intent;
        try {
            intent = parseIntent(input);
        }
        catch (e) {
            const inj = checkInjection(context, this.policy);
            const message = e instanceof IntentError ? e.message : String(e);
            return { report: this.blocked([res("intent-schema", "Intent schema", "fail", message), inj.check], "Invalid intent", {}, input) };
        }
        if (isAuthorityIntent(intent))
            return { intent, report: this.authorityReport(intent, context) };
        const pre = this.precheckIntent(intent, context);
        if (pre.some((c) => c.status === "fail")) {
            const extra = intent.action === "transfer" ? { recipient: intent.to } : {};
            return { intent, report: this.blocked(pre, intent.action === "swap" ? "Swap" : "Transfer", extra, intent) };
        }
        const self = this.selfKey();
        if (!self)
            return { intent, report: this.blocked([res("build", "Transaction build", "fail", "No signer public key configured")], intent.action, {}, intent) };
        try {
            let wire;
            if (intent.action === "transfer") {
                if (!this.rpc)
                    throw new BuildError("An RPC is required to build transfers (recent blockhash)");
                wire = await buildTransfer(intent, this.policy, self, this.rpc);
            }
            else {
                if (!this.swapProvider)
                    throw new BuildError("No swap provider configured");
                wire = await buildSwap(intent, this.policy, self, this.swapProvider);
            }
            const report = await this.inspect(wire, { intent, context, self });
            return { intent, report, transaction: wire };
        }
        catch (e) {
            return { intent, report: this.blocked([res("build", "Transaction build", "fail", e.message)], intent.action, {}, intent) };
        }
    }
    /** Build → inspect → (only if ALLOW) sign → send. REVIEW and BLOCK verdicts are never signed. */
    async execute(input, context) {
        const decision = await this.evaluateIntent(input, context);
        if (decision.report.verdict !== "ALLOW" || !decision.transaction)
            return decision;
        if (!this.signer || !this.rpc)
            throw new Error("execute() requires both a signer and an rpc");
        const signed = await signWire(decision.transaction, this.signer);
        const signature = await this.rpc.sendTransaction(signed);
        this.ledger?.record(BigInt(decision.report.summary.solOutLamports));
        return { ...decision, signature };
    }
    precheckIntent(intent, context) {
        const checks = [];
        const { policy } = this;
        const allowed = new Set(policy.destinations.allow.map((d) => d.address));
        const assetRef = intent.action === "transfer" ? intent.asset : intent.input;
        const asset = resolveAsset(policy, assetRef);
        const problems = [];
        if (!asset)
            problems.push(`Asset ${assetRef} is not allowlisted`);
        if (intent.action === "swap" && !resolveAsset(policy, intent.output))
            problems.push(`Asset ${intent.output} is not allowlisted`);
        if (asset) {
            const raw = parseUnits(intent.amount, asset.decimals);
            const limit = asset.native ? policy.limits.maxSolPerTx : policy.tokens[asset.symbol]?.maxPerTx;
            if (limit && raw > parseUnits(limit, asset.decimals))
                problems.push(`${intent.amount} ${asset.symbol} exceeds the per-transaction limit of ${limit}`);
        }
        checks.push(problems.length
            ? res("amount-limit", "Amount limit", "fail", problems[0], problems)
            : res("amount-limit", "Amount limit", "pass", "Intent amount within limits"));
        if (intent.action === "transfer") {
            checks.push(allowed.has(intent.to)
                ? res("destination", "Destination allowlist", "pass", "Recipient is allowlisted")
                : res("destination", "Destination allowlist", "fail", `Destination not allowlisted: ${intent.to}`));
        }
        const inj = checkInjection(context, policy);
        checks.push(inj.check, checkProvenance(intentAddresses(intent), context, allowed, this.selfKey() ?? ""));
        return checks;
    }
    authorityReport(intent, context) {
        const allowed = new Set(this.policy.destinations.allow.map((d) => d.address));
        const unlimited = !intent.amount || /^(unlimited|max|maximum|infinite|all)$/i.test(intent.amount);
        const checks = [
            res("instruction-allowlist", "Instruction allowlist", "fail", `Unexpected ${intent.action === "approve" ? "approval" : intent.action} instruction: agents may only request transfer or swap`),
            intent.spender && allowed.has(intent.spender)
                ? res("destination", "Destination allowlist", "pass", "Address is allowlisted")
                : res("destination", "Destination allowlist", "fail", `Destination not allowlisted${intent.spender ? `: ${intent.spender}` : ""}`),
            res("authority", "Authority escalation", "fail", `Authority escalation detected${unlimited ? " (unlimited spending authority)" : ""}`, [`action: ${intent.action}`, ...(intent.spender ? [`spender: ${intent.spender}`] : []), ...(intent.amount ? [`amount: ${intent.amount}`] : [])], true),
        ];
        const inj = checkInjection(context, this.policy);
        checks.push(inj.check, checkProvenance(intentAddresses(intent), context, allowed, this.selfKey() ?? ""));
        const report = assembleReport({
            checks,
            summary: { ...emptySummary(`Blocked: ${intent.action}`), recipient: intent.spender },
            instructions: [],
            injection: inj.findings,
        });
        this.audit(report, intent);
        return report;
    }
}
function intentAddresses(intent) {
    if (isAuthorityIntent(intent))
        return intent.spender ? [intent.spender] : [];
    return intent.action === "transfer" ? [intent.to] : [];
}
//# sourceMappingURL=firewall.js.map