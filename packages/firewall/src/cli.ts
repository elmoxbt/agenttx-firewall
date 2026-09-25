#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { AgentTxFirewall } from "./firewall.js";
import { JupiterSwapProvider } from "./jupiter.js";
import { defaultPolicy, loadPolicy, resolvePolicy, type Policy } from "./policy/policy.js";
import { renderReport } from "./report.js";
import { scanText } from "./guard/injection.js";
import { parseTransactionInput, toTransactionJson } from "./txfile.js";
import { parseIntent } from "./intent/intent.js";
import type { Cluster, SecurityReport } from "./types.js";

const VERSION = "0.1.0";

const HELP = `agenttx ${VERSION} — a firewall between AI agents and Solana signers

USAGE
  agenttx inspect <tx.json|->   Inspect a transaction (base64 or JSON) and print a security report
  agenttx intent <intent.json>  Build a transaction from an agent intent, then inspect it
  agenttx scan <file|->         Scan untrusted text (tool output, web page) for wallet-targeted injection
  agenttx init                  Write a starter policy file

OPTIONS
  --policy <file>        Policy JSON (default: built-in conservative policy)
  --rpc <url|cluster>    RPC endpoint or one of: devnet, mainnet, testnet, localnet
  --signer <pubkey>      Agent signer public key (default: policy.signer, else the fee payer)
  --simulate / --no-simulate   Force simulation on or off (default: on when --rpc is given)
  --intent <file>        (inspect) Also verify the transaction matches this intent
  --context <file>       (inspect, intent) Untrusted text the agent has seen; repeatable
  --trusted <text>       (inspect, intent) The operator's own instruction
  --out <file>           (intent) Save the built transaction; (init) policy output path
  --cluster <name>       (init) mainnet-beta | devnet | testnet | localnet
  --jupiter-url <url>    (intent) Jupiter swap API base URL
  --jupiter-key <key>    (intent) Jupiter API key (or env JUPITER_API_KEY)
  --json                 Print the report as JSON
  --no-color             Disable ANSI colors
  -h, --help / -v, --version

EXIT CODES
  0 ALLOW   1 BLOCK   2 REVIEW   64 usage or input error`;

interface Args {
  cmd?: string;
  positional: string[];
  flags: Map<string, string[]>;
  bools: Set<string>;
}

const BOOLEAN_FLAGS = new Set(["json", "no-color", "simulate", "no-simulate", "help", "version", "h", "v"]);

function parseArgs(argv: string[]): Args {
  const out: Args = { positional: [], flags: new Map(), bools: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-") out.positional.push(a);
    else if (a.startsWith("-")) {
      const key = a.replace(/^-+/, "");
      if (BOOLEAN_FLAGS.has(key)) out.bools.add(key);
      else {
        const v = argv[++i];
        if (v === undefined) throw new UsageError(`Flag ${a} needs a value`);
        out.flags.set(key, [...(out.flags.get(key) ?? []), v]);
      }
    } else if (!out.cmd) out.cmd = a;
    else out.positional.push(a);
  }
  return out;
}

class UsageError extends Error {}

const flag = (a: Args, k: string) => a.flags.get(k)?.[0];

function readInput(path: string): string {
  return path === "-" ? readFileSync(0, "utf8") : readFileSync(path, "utf8");
}

function makeFirewall(a: Args, withSwap = false): AgentTxFirewall {
  let policy: Policy = a.flags.has("policy") ? loadPolicy(flag(a, "policy")!) : resolvePolicy({});
  const signer = flag(a, "signer");
  if (signer) policy = resolvePolicy({ ...policy, signer });
  const rpc = flag(a, "rpc");
  return new AgentTxFirewall({
    policy,
    rpc,
    swapProvider: withSwap
      ? new JupiterSwapProvider({ baseUrl: flag(a, "jupiter-url"), apiKey: flag(a, "jupiter-key") ?? process.env.JUPITER_API_KEY })
      : undefined,
  });
}

function context(a: Args) {
  const files = a.flags.get("context") ?? [];
  const trusted = flag(a, "trusted");
  return files.length || trusted ? { untrusted: files.map((f) => readFileSync(f, "utf8")), trusted } : undefined;
}

function print(a: Args, report: SecurityReport): void {
  if (a.bools.has("json")) console.log(JSON.stringify(report, null, 2));
  else {
    const color = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && !a.bools.has("no-color");
    console.log(renderReport(report, { color }));
  }
  process.exitCode = report.verdict === "ALLOW" ? 0 : report.verdict === "BLOCK" ? 1 : 2;
}

async function main(): Promise<void> {
  const a = parseArgs(process.argv.slice(2));
  if (a.bools.has("version") || a.bools.has("v")) return void console.log(VERSION);
  if (!a.cmd || a.bools.has("help") || a.bools.has("h") || a.cmd === "help") return void console.log(HELP);

  switch (a.cmd) {
    case "inspect": {
      const file = a.positional[0];
      if (!file) throw new UsageError("inspect needs a transaction file (or - for stdin)");
      const fw = makeFirewall(a);
      const wire = parseTransactionInput(readInput(file));
      const intent = flag(a, "intent") ? parseIntent(readFileSync(flag(a, "intent")!, "utf8")) : undefined;
      const simulate = a.bools.has("no-simulate") ? false : a.bools.has("simulate") ? true : undefined;
      return print(a, await fw.inspect(wire, { intent, context: context(a), simulate }));
    }
    case "intent": {
      const file = a.positional[0];
      if (!file) throw new UsageError("intent needs an intent JSON file (or - for stdin)");
      const fw = makeFirewall(a, true);
      const decision = await fw.evaluateIntent(readInput(file), context(a));
      if (flag(a, "out") && decision.transaction) writeFileSync(flag(a, "out")!, toTransactionJson(decision.transaction));
      return print(a, decision.report);
    }
    case "scan": {
      const file = a.positional[0];
      if (!file) throw new UsageError("scan needs a file (or - for stdin)");
      const r = scanText(readInput(file));
      if (a.bools.has("json")) console.log(JSON.stringify(r, null, 2));
      else {
        console.log(`Highest severity: ${r.highest}`);
        for (const f of r.findings) console.log(`  [${f.severity}] ${f.rule}: ${f.description}\n         "${f.excerpt}"`);
        if (r.addresses.length) console.log(`Addresses mentioned: ${r.addresses.join(", ")}`);
      }
      process.exitCode = r.highest === "high" ? 1 : r.highest === "medium" ? 2 : 0;
      return;
    }
    case "init": {
      const cluster = (flag(a, "cluster") ?? "devnet") as Cluster;
      const policy = defaultPolicy(cluster);
      const signer = flag(a, "signer");
      const out = flag(a, "out") ?? "agenttx.policy.json";
      writeFileSync(out, `${JSON.stringify(signer ? { ...policy, signer } : policy, null, 2)}\n`);
      console.log(`Wrote ${out} (cluster: ${cluster}). Add your destinations.allow entries before use.`);
      return;
    }
    default:
      throw new UsageError(`Unknown command "${a.cmd}"`);
  }
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  console.error(`agenttx: ${msg}`);
  if (e instanceof UsageError) console.error("Run `agenttx --help` for usage.");
  process.exitCode = 64;
});
