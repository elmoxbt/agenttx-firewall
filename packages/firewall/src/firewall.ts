import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { buildSwap, buildTransfer, BuildError, type SwapProvider } from "./builder.js";
import {
  buildCheckContext,
  checkAmounts,
  checkAuthority,
  checkDestinations,
  checkInjection,
  checkInstructions,
  checkIntentMatch,
  checkPriorityFee,
  checkPrograms,
  checkProvenance,
  checkStructure,
  checkSwap,
  checkTokens,
  outsideAddresses,
  res,
  runSimulation,
} from "./checks.js";
import { isAuthorityIntent, parseIntent, IntentError, type AuthorityIntent, type Intent } from "./intent/intent.js";
import { scanText, type ScanResult } from "./guard/injection.js";
import { SpendingLedger } from "./ledger.js";
import { resolveAsset, resolvePolicy, type Policy } from "./policy/policy.js";
import { assembleReport, buildSummary, summarizeInstructions } from "./report.js";
import { HttpRpc, type Rpc } from "./solana/rpc.js";
import { decodeAll } from "./solana/decode.js";
import {
  applyLookups,
  hasLookups,
  parseLookupTableAddresses,
  parseTransaction,
  requiredSigners,
  resolveInstructions,
  type LoadedAddresses,
  type ParsedTransaction,
} from "./solana/transaction.js";
import { GuardedSigner, signWire, type Signer } from "./signer.js";
import type { CheckResult, SecurityReport, TxSummary, UntrustedContext } from "./types.js";
import { fromBase64 } from "./util/bytes.js";
import { parseUnits } from "./util/units.js";

export interface AuditEntry {
  timestamp: string;
  verdict: SecurityReport["verdict"];
  risk: SecurityReport["risk"];
  action: string;
  reasons: string[];
  intent?: unknown;
}

export interface FirewallOptions {
  /** A full or partial policy object; merged over safe defaults and validated. */
  policy?: unknown;
  rpc?: Rpc | string;
  signer?: Signer;
  swapProvider?: SwapProvider;
  ledger?: SpendingLedger;
  /** Path of a JSONL file, or a callback, that receives every decision. */
  auditLog?: string | ((entry: AuditEntry) => void);
}

export interface InspectOptions {
  intent?: Intent;
  context?: UntrustedContext;
  /** Run RPC simulation (default: true when an RPC is configured). */
  simulate?: boolean;
  /** Override the agent's public key for this call. */
  self?: string;
}

export interface IntentDecision {
  intent?: Intent;
  report: SecurityReport;
  /** Unsigned transaction built by the firewall (only present when it was built). */
  transaction?: Uint8Array;
}

export interface ExecuteResult extends IntentDecision {
  signature?: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const emptySummary = (action: string): TxSummary => ({
  programs: ["(none)"],
  action,
  solOut: "0 SOL",
  solOutLamports: "0",
  signers: [],
  instructionCount: 0,
});

export class AgentTxFirewall {
  readonly policy: Policy;
  readonly rpc?: Rpc;
  readonly signer?: Signer;
  private readonly swapProvider?: SwapProvider;
  private readonly ledger?: SpendingLedger;
  private readonly auditLog?: FirewallOptions["auditLog"];

  constructor(opts: FirewallOptions = {}) {
    this.policy = resolvePolicy(opts.policy ?? {});
    this.rpc = typeof opts.rpc === "string" ? new HttpRpc(opts.rpc) : opts.rpc;
    this.signer = opts.signer;
    this.swapProvider = opts.swapProvider;
    this.ledger = opts.ledger;
    this.auditLog = opts.auditLog;
  }

  /** Scan text the agent has read (tool output, web pages, emails) for wallet-targeted injection. */
  scan(text: string): ScanResult {
    return scanText(text);
  }

  /** Wrap a signer so an agent can only obtain signatures through this firewall. */
  guard(signer: Signer | undefined = this.signer, opts: { allowReview?: boolean } = {}): GuardedSigner {
    if (!signer) throw new Error("guard() needs a signer");
    return new GuardedSigner(signer, this, opts);
  }

  private selfKey(override?: string): string | undefined {
    return override ?? this.policy.signer ?? this.signer?.publicKey;
  }

  private audit(report: SecurityReport, intent?: unknown): void {
    if (!this.auditLog) return;
    const entry: AuditEntry = {
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
      } else this.auditLog(entry);
    } catch {
      /* auditing must never break the decision path */
    }
  }

  private blocked(checks: CheckResult[], action: string, extra: Partial<TxSummary> = {}, intent?: unknown): SecurityReport {
    const report = assembleReport({ checks, summary: { ...emptySummary(action), ...extra }, instructions: [] });
    this.audit(report, intent);
    return report;
  }

  // -------------------------------------------------------------------------------------------
  // Transaction inspection
  // -------------------------------------------------------------------------------------------
  async inspect(input: Uint8Array | string, opts: InspectOptions = {}): Promise<SecurityReport> {
    let wire: Uint8Array;
    let tx: ParsedTransaction;
    try {
      wire = typeof input === "string" ? fromBase64(input) : input;
      tx = parseTransaction(wire);
    } catch (e) {
      return this.blocked([res("structure", "Transaction structure", "fail", `Unparseable transaction: ${(e as Error).message}`)], "Unknown");
    }
    const signers = requiredSigners(tx);
    const self = this.selfKey(opts.self) ?? tx.staticAccountKeys[0];

    let loaded: LoadedAddresses | undefined;
    let unresolved = false;
    if (hasLookups(tx)) {
      if (!this.rpc) unresolved = true;
      else {
        try {
          const tables = new Map<string, string[]>();
          for (const l of tx.addressTableLookups) {
            const info = await this.rpc.getAccountInfo(l.accountKey);
            if (!info) throw new Error(`lookup table ${l.accountKey} not found`);
            tables.set(l.accountKey, parseLookupTableAddresses(info.data));
          }
          loaded = applyLookups(tx, tables);
        } catch {
          unresolved = true;
        }
      }
    }

    let decoded;
    try {
      decoded = decodeAll(resolveInstructions(tx, loaded));
    } catch (e) {
      return this.blocked([res("structure", "Transaction structure", "fail", `Cannot decode instructions: ${(e as Error).message}`)], "Unknown");
    }

    const spentInWindow = this.ledger && this.policy.limits.maxSolPerDay ? this.ledger.spentSince(DAY_MS) : undefined;
    const ctx = buildCheckContext({ policy: this.policy, self, tx, signers, decoded, unresolvedLookups: unresolved, intent: opts.intent, spentInWindow });

    const checks: CheckResult[] = [
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
    if (opts.intent) suspects.push(...intentAddresses(opts.intent));
    checks.push(checkProvenance(suspects, opts.context, ctx.allowed, self));

    const staticFailed = checks.some((c) => c.status === "fail");
    let simulation;
    if ((opts.simulate ?? Boolean(this.rpc)) && !staticFailed) {
      const r = await runSimulation(ctx, this.rpc, wire);
      checks.push(r.check);
      simulation = r.summary;
    } else if (staticFailed) {
      checks.push(res("simulation", "Simulation", "skip", "Skipped because static checks failed"));
    } else {
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
  async evaluateIntent(input: unknown, context?: UntrustedContext): Promise<IntentDecision> {
    let intent: Intent;
    try {
      intent = parseIntent(input);
    } catch (e) {
      const inj = checkInjection(context, this.policy);
      const message = e instanceof IntentError ? e.message : String(e);
      return { report: this.blocked([res("intent-schema", "Intent schema", "fail", message), inj.check], "Invalid intent", {}, input) };
    }

    if (isAuthorityIntent(intent)) return { intent, report: this.authorityReport(intent, context) };

    const pre = this.precheckIntent(intent, context);
    if (pre.some((c) => c.status === "fail")) {
      const extra: Partial<TxSummary> = intent.action === "transfer" ? { recipient: intent.to } : {};
      return { intent, report: this.blocked(pre, intent.action === "swap" ? "Swap" : "Transfer", extra, intent) };
    }

    const self = this.selfKey();
    if (!self) return { intent, report: this.blocked([res("build", "Transaction build", "fail", "No signer public key configured")], intent.action, {}, intent) };
    try {
      let wire: Uint8Array;
      if (intent.action === "transfer") {
        if (!this.rpc) throw new BuildError("An RPC is required to build transfers (recent blockhash)");
        wire = await buildTransfer(intent, this.policy, self, this.rpc);
      } else {
        if (!this.swapProvider) throw new BuildError("No swap provider configured");
        wire = await buildSwap(intent, this.policy, self, this.swapProvider);
      }
      const report = await this.inspect(wire, { intent, context, self });
      return { intent, report, transaction: wire };
    } catch (e) {
      return { intent, report: this.blocked([res("build", "Transaction build", "fail", (e as Error).message)], intent.action, {}, intent) };
    }
  }

  /** Build → inspect → (only if ALLOW) sign → send. REVIEW and BLOCK verdicts are never signed. */
  async execute(input: unknown, context?: UntrustedContext): Promise<ExecuteResult> {
    const decision = await this.evaluateIntent(input, context);
    if (decision.report.verdict !== "ALLOW" || !decision.transaction) return decision;
    if (!this.signer || !this.rpc) throw new Error("execute() requires both a signer and an rpc");
    const signed = await signWire(decision.transaction, this.signer);
    const signature = await this.rpc.sendTransaction(signed);
    this.ledger?.record(BigInt(decision.report.summary.solOutLamports));
    return { ...decision, signature };
  }

  private precheckIntent(intent: Exclude<Intent, AuthorityIntent>, context?: UntrustedContext): CheckResult[] {
    const checks: CheckResult[] = [];
    const { policy } = this;
    const allowed = new Set(policy.destinations.allow.map((d) => d.address));
    const assetRef = intent.action === "transfer" ? intent.asset : intent.input;
    const asset = resolveAsset(policy, assetRef);
    const problems: string[] = [];
    if (!asset) problems.push(`Asset ${assetRef} is not allowlisted`);
    if (intent.action === "swap" && !resolveAsset(policy, intent.output)) problems.push(`Asset ${intent.output} is not allowlisted`);
    if (asset) {
      const raw = parseUnits(intent.amount, asset.decimals);
      const limit = asset.native ? policy.limits.maxSolPerTx : policy.tokens[asset.symbol]?.maxPerTx;
      if (limit && raw > parseUnits(limit, asset.decimals)) problems.push(`${intent.amount} ${asset.symbol} exceeds the per-transaction limit of ${limit}`);
    }
    checks.push(
      problems.length
        ? res("amount-limit", "Amount limit", "fail", problems[0], problems)
        : res("amount-limit", "Amount limit", "pass", "Intent amount within limits"),
    );
    if (intent.action === "transfer") {
      checks.push(
        allowed.has(intent.to)
          ? res("destination", "Destination allowlist", "pass", "Recipient is allowlisted")
          : res("destination", "Destination allowlist", "fail", `Destination not allowlisted: ${intent.to}`),
      );
    }
    const inj = checkInjection(context, policy);
    checks.push(inj.check, checkProvenance(intentAddresses(intent), context, allowed, this.selfKey() ?? ""));
    return checks;
  }

  private authorityReport(intent: AuthorityIntent, context?: UntrustedContext): SecurityReport {
    const allowed = new Set(this.policy.destinations.allow.map((d) => d.address));
    const unlimited = !intent.amount || /^(unlimited|max|maximum|infinite|all)$/i.test(intent.amount);
    const checks: CheckResult[] = [
      res("instruction-allowlist", "Instruction allowlist", "fail", `Unexpected ${intent.action === "approve" ? "approval" : intent.action} instruction: agents may only request transfer or swap`),
      intent.spender && allowed.has(intent.spender)
        ? res("destination", "Destination allowlist", "pass", "Address is allowlisted")
        : res("destination", "Destination allowlist", "fail", `Destination not allowlisted${intent.spender ? `: ${intent.spender}` : ""}`),
      res(
        "authority",
        "Authority escalation",
        "fail",
        `Authority escalation detected${unlimited ? " (unlimited spending authority)" : ""}`,
        [`action: ${intent.action}`, ...(intent.spender ? [`spender: ${intent.spender}`] : []), ...(intent.amount ? [`amount: ${intent.amount}`] : [])],
        true,
      ),
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

function intentAddresses(intent: Intent): string[] {
  if (isAuthorityIntent(intent)) return intent.spender ? [intent.spender] : [];
  return intent.action === "transfer" ? [intent.to] : [];
}
