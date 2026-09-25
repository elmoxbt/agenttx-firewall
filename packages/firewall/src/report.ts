import type { CheckContext } from "./checks.js";
import { solOutLamports } from "./checks.js";
import { decimalsForMint, symbolForMint, type Policy } from "./policy/policy.js";
import { INFRA_PROGRAMS } from "./solana/constants.js";
import { describeInstruction, type DecodedInstruction } from "./solana/decode.js";
import type {
  CheckResult,
  InjectionFinding,
  InstructionSummary,
  Risk,
  SecurityReport,
  SimulationSummary,
  TxSummary,
  Verdict,
} from "./types.js";
import { shortAddr } from "./util/base58.js";
import { formatUnits } from "./util/units.js";

export function computeVerdict(checks: CheckResult[]): { verdict: Verdict; risk: Risk } {
  const fails = checks.filter((c) => c.status === "fail");
  const warns = checks.filter((c) => c.status === "warn");
  if (fails.length) return { verdict: "BLOCK", risk: fails.some((c) => c.critical) ? "CRITICAL" : "HIGH" };
  if (warns.length) return { verdict: "REVIEW", risk: "MEDIUM" };
  return { verdict: "ALLOW", risk: "LOW" };
}

function amountLabel(policy: Policy, mint: string | undefined, raw: bigint): string {
  if (!mint) return `${raw} raw units`;
  const decimals = decimalsForMint(policy, mint);
  const symbol = symbolForMint(policy, mint) ?? shortAddr(mint);
  return decimals === undefined ? `${raw} raw units of ${symbol}` : `${formatUnits(raw, decimals)} ${symbol}`;
}

export function buildSummary(ctx: CheckContext): TxSummary {
  const { policy, decoded } = ctx;
  const app = [...new Set(decoded.filter((d) => !INFRA_PROGRAMS.has(d.programId)).map((d) => d.programLabel))];
  const programs = app.length ? app : [...new Set(decoded.map((d) => d.programLabel))];
  const out = solOutLamports(ctx);
  const summary: TxSummary = {
    programs,
    action: "Unknown",
    solOut: `${formatUnits(out, 9)} SOL`,
    solOutLamports: out.toString(),
    feePayer: ctx.feePayer,
    signers: ctx.signers,
    instructionCount: decoded.length,
  };
  const find = <T extends DecodedInstruction["parsed"]["type"]>(t: T) =>
    decoded.find((d) => d.parsed.type === t)?.parsed as Extract<DecodedInstruction["parsed"], { type: T }> | undefined;

  const swap = find("swap_route");
  const transfer = decoded.find((d) => d.parsed.type === "sol_transfer" && d.parsed.from === ctx.self)?.parsed;
  const token = find("token_transfer");
  if (swap) {
    summary.action = "Swap";
    const spend = swap.mode === "exact_in" ? swap.amount : swap.otherAmount;
    summary.input = swap.sourceMint
      ? amountLabel(policy, swap.sourceMint, spend)
      : out > 0n
        ? `${formatUnits(out, 9)} SOL (wrapped)`
        : `${spend} raw units`;
    summary.expectedOutput = swap.destinationMint ? (symbolForMint(policy, swap.destinationMint) ?? swap.destinationMint) : "unknown token";
  } else if (find("token_approve")) {
    summary.action = "Approve token spending";
    const a = find("token_approve")!;
    summary.recipient = a.delegate;
  } else if (find("authority_change")) {
    summary.action = "Change authority";
  } else if (transfer && transfer.type === "sol_transfer") {
    summary.action = "Transfer SOL";
    summary.input = `${formatUnits(transfer.lamports, 9)} SOL`;
    summary.recipient = transfer.to;
  } else if (token) {
    summary.action = "Transfer token";
    summary.input = amountLabel(policy, token.mint, token.amount);
    summary.recipient = token.destination;
  } else {
    const names = decoded.filter((d) => !["compute_limit", "compute_price"].includes(d.parsed.type)).map((d) => d.name);
    if (names.length) summary.action = names.join(", ");
  }
  return summary;
}

export function summarizeInstructions(decoded: DecodedInstruction[]): InstructionSummary[] {
  return decoded.map((d) => ({ index: d.index, program: d.programLabel, name: d.name, description: describeInstruction(d) }));
}

export function assembleReport(args: {
  checks: CheckResult[];
  summary: TxSummary;
  instructions: InstructionSummary[];
  injection?: InjectionFinding[];
  simulation?: SimulationSummary;
}): SecurityReport {
  const { verdict, risk } = computeVerdict(args.checks);
  return {
    verdict,
    risk,
    summary: args.summary,
    checks: args.checks,
    reasons: args.checks.filter((c) => c.status === "fail").map((c) => `${c.name}: ${c.message}`),
    instructions: args.instructions,
    injection: args.injection ?? [],
    simulation: args.simulation ?? { ran: false },
    timestamp: new Date().toISOString(),
  };
}

const TAG: Record<CheckResult["status"], string> = { pass: "PASS", warn: "WARN", fail: "FAIL", skip: "SKIP" };
const COLOR: Record<string, string> = { pass: "32", warn: "33", fail: "31", skip: "90" };

export function renderReport(r: SecurityReport, opts: { color?: boolean; verbose?: boolean } = {}): string {
  const c = (code: string, s: string) => (opts.color ? `\u001b[${code}m${s}\u001b[0m` : s);
  const lines: string[] = [c("1", "AGENTTX SECURITY REPORT"), ""];
  const s = r.summary;
  lines.push(`Program: ${s.programs.join(", ")}`);
  lines.push(`Action: ${s.action}`);
  if (s.input) lines.push(`Input: ${s.input}`);
  if (s.expectedOutput) lines.push(`Expected output: ${s.expectedOutput}`);
  if (s.recipient) lines.push(`Recipient: ${s.recipient}`);
  lines.push("");
  for (const ch of r.checks) {
    lines.push(`${c(COLOR[ch.status], `[${TAG[ch.status]}]`)} ${ch.name}${ch.status === "pass" ? "" : ` — ${ch.message}`}`);
    if (opts.verbose || ch.status === "fail" || ch.status === "warn") {
      for (const d of ch.details ?? []) {
        if (d.replace(/^#\d+ /, "") !== ch.message) lines.push(`       ${d}`);
      }
    }
  }
  lines.push("");
  const riskColor = r.risk === "LOW" ? "32" : r.risk === "MEDIUM" ? "33" : "31";
  lines.push(`RISK: ${c(riskColor, r.risk)}`);
  lines.push(`VERDICT: ${c(r.verdict === "ALLOW" ? "32" : r.verdict === "REVIEW" ? "33" : "31", r.verdict === "BLOCK" ? "BLOCKED" : r.verdict)}`);
  if (r.reasons.length) {
    lines.push("", "Reasons:");
    for (const reason of r.reasons) lines.push(`  - ${reason}`);
  }
  return lines.join("\n");
}
