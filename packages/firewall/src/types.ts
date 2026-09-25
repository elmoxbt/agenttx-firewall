export type Cluster = "mainnet-beta" | "devnet" | "testnet" | "localnet";
export type CheckStatus = "pass" | "warn" | "fail" | "skip";
export type Verdict = "ALLOW" | "REVIEW" | "BLOCK";
export type Risk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Severity = "low" | "medium" | "high";

export interface CheckResult {
  id: string;
  name: string;
  status: CheckStatus;
  message: string;
  details?: string[];
  /** A failing critical check (authority escalation, injection) raises risk to CRITICAL. */
  critical?: boolean;
}

export interface InjectionFinding {
  rule: string;
  severity: Severity;
  description: string;
  excerpt: string;
}

export interface InstructionSummary {
  index: number;
  program: string;
  name: string;
  description: string;
}

export interface TxSummary {
  programs: string[];
  action: string;
  input?: string;
  expectedOutput?: string;
  recipient?: string;
  solOut: string;
  /** Exact lamports leaving the agent wallet through visible System Program instructions. */
  solOutLamports: string;
  feePayer?: string;
  signers: string[];
  instructionCount: number;
}

export interface SimulationSummary {
  ran: boolean;
  ok?: boolean;
  unitsConsumed?: number;
  solChangeLamports?: string;
  cpiPrograms?: string[];
  error?: string;
}

export interface SecurityReport {
  verdict: Verdict;
  risk: Risk;
  summary: TxSummary;
  checks: CheckResult[];
  /** Human-readable reasons for every failed check. */
  reasons: string[];
  instructions: InstructionSummary[];
  injection: InjectionFinding[];
  simulation: SimulationSummary;
  timestamp: string;
}

/** Text the agent has seen that did NOT come from the human operator (tool output, web pages, emails...). */
export interface UntrustedContext {
  untrusted?: string[];
  /** The operator's own instruction, if available. Addresses found here are considered user-provided. */
  trusted?: string;
}
