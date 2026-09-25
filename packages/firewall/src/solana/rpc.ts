import { CLUSTER_RPC } from "./constants.js";
import type { Cluster } from "../types.js";
import { fromBase64, toBase64 } from "../util/bytes.js";

export interface AccountInfo {
  lamports: bigint;
  owner: string;
  data: Uint8Array;
}

export interface SimulationResult {
  err: unknown | null;
  logs: string[];
  unitsConsumed?: number;
  /** Post-simulation lamports for the requested accounts (null if the account does not exist). */
  accounts: ({ lamports: bigint } | null)[];
}

/** The small slice of Solana JSON-RPC the firewall needs. Implement it to plug in any RPC client. */
export interface Rpc {
  getLatestBlockhash(): Promise<{ blockhash: string; lastValidBlockHeight: number }>;
  getAccountInfo(address: string): Promise<AccountInfo | null>;
  getBalance(address: string): Promise<bigint>;
  simulateTransaction(wire: Uint8Array, opts: { accounts: string[] }): Promise<SimulationResult>;
  sendTransaction(wire: Uint8Array): Promise<string>;
}

export function resolveRpcUrl(input: string): string {
  const key = input === "mainnet" ? "mainnet-beta" : input;
  return key in CLUSTER_RPC ? CLUSTER_RPC[key as Cluster] : input;
}

export class HttpRpc implements Rpc {
  readonly url: string;
  constructor(
    urlOrCluster: string,
    private readonly opts: { headers?: Record<string, string>; fetchImpl?: typeof fetch } = {},
  ) {
    this.url = resolveRpcUrl(urlOrCluster);
  }

  private async call<T>(method: string, params: unknown[]): Promise<T> {
    const f = this.opts.fetchImpl ?? fetch;
    const res = await f(this.url, {
      method: "POST",
      headers: { "content-type": "application/json", ...this.opts.headers },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!res.ok) throw new Error(`RPC HTTP ${res.status} ${res.statusText}`);
    const json = (await res.json()) as { result?: T; error?: { message: string } };
    if (json.error) throw new Error(`RPC ${method} failed: ${json.error.message}`);
    return json.result as T;
  }

  async getLatestBlockhash() {
    const r = await this.call<{ value: { blockhash: string; lastValidBlockHeight: number } }>("getLatestBlockhash", [
      { commitment: "confirmed" },
    ]);
    return r.value;
  }

  async getAccountInfo(address: string): Promise<AccountInfo | null> {
    const r = await this.call<{ value: { lamports: number; owner: string; data: [string, string] } | null }>(
      "getAccountInfo",
      [address, { encoding: "base64", commitment: "confirmed" }],
    );
    if (!r.value) return null;
    return { lamports: BigInt(r.value.lamports), owner: r.value.owner, data: fromBase64(r.value.data[0]) };
  }

  async getBalance(address: string): Promise<bigint> {
    const r = await this.call<{ value: number }>("getBalance", [address, { commitment: "confirmed" }]);
    return BigInt(r.value);
  }

  async simulateTransaction(wire: Uint8Array, opts: { accounts: string[] }): Promise<SimulationResult> {
    const r = await this.call<{
      value: {
        err: unknown | null;
        logs: string[] | null;
        unitsConsumed?: number;
        accounts?: ({ lamports: number } | null)[];
      };
    }>("simulateTransaction", [
      toBase64(wire),
      {
        encoding: "base64",
        sigVerify: false,
        replaceRecentBlockhash: true,
        commitment: "confirmed",
        accounts: { encoding: "base64", addresses: opts.accounts },
      },
    ]);
    return {
      err: r.value.err,
      logs: r.value.logs ?? [],
      unitsConsumed: r.value.unitsConsumed,
      accounts: (r.value.accounts ?? []).map((a) => (a ? { lamports: BigInt(a.lamports) } : null)),
    };
  }

  async sendTransaction(wire: Uint8Array): Promise<string> {
    return this.call<string>("sendTransaction", [
      toBase64(wire),
      { encoding: "base64", preflightCommitment: "confirmed", maxRetries: 3 },
    ]);
  }
}
