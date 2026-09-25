import { CLUSTER_RPC } from "./constants.js";
import { fromBase64, toBase64 } from "../util/bytes.js";
export function resolveRpcUrl(input) {
    const key = input === "mainnet" ? "mainnet-beta" : input;
    return key in CLUSTER_RPC ? CLUSTER_RPC[key] : input;
}
export class HttpRpc {
    opts;
    url;
    constructor(urlOrCluster, opts = {}) {
        this.opts = opts;
        this.url = resolveRpcUrl(urlOrCluster);
    }
    async call(method, params) {
        const f = this.opts.fetchImpl ?? fetch;
        const res = await f(this.url, {
            method: "POST",
            headers: { "content-type": "application/json", ...this.opts.headers },
            body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
        if (!res.ok)
            throw new Error(`RPC HTTP ${res.status} ${res.statusText}`);
        const json = (await res.json());
        if (json.error)
            throw new Error(`RPC ${method} failed: ${json.error.message}`);
        return json.result;
    }
    async getLatestBlockhash() {
        const r = await this.call("getLatestBlockhash", [
            { commitment: "confirmed" },
        ]);
        return r.value;
    }
    async getAccountInfo(address) {
        const r = await this.call("getAccountInfo", [address, { encoding: "base64", commitment: "confirmed" }]);
        if (!r.value)
            return null;
        return { lamports: BigInt(r.value.lamports), owner: r.value.owner, data: fromBase64(r.value.data[0]) };
    }
    async getBalance(address) {
        const r = await this.call("getBalance", [address, { commitment: "confirmed" }]);
        return BigInt(r.value);
    }
    async simulateTransaction(wire, opts) {
        const r = await this.call("simulateTransaction", [
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
    async sendTransaction(wire) {
        return this.call("sendTransaction", [
            toBase64(wire),
            { encoding: "base64", preflightCommitment: "confirmed", maxRetries: 3 },
        ]);
    }
}
//# sourceMappingURL=rpc.js.map