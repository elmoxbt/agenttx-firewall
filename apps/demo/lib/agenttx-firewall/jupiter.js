import { fromBase64 } from "./util/bytes.js";
/**
 * Fetches a quote + ready-made swap transaction from Jupiter. Nothing it returns is trusted:
 * the quote is sanity-checked here and the transaction is fully re-inspected by the firewall.
 */
export class JupiterSwapProvider {
    opts;
    constructor(opts = {}) {
        this.opts = opts;
    }
    async request(path, init) {
        const base = (this.opts.baseUrl ?? "https://lite-api.jup.ag/swap/v1").replace(/\/$/, "");
        const headers = { "content-type": "application/json" };
        if (this.opts.apiKey)
            headers["x-api-key"] = this.opts.apiKey;
        const res = await (this.opts.fetchImpl ?? fetch)(`${base}${path}`, { headers, ...init });
        if (!res.ok)
            throw new Error(`Jupiter API ${res.status}: ${(await res.text()).slice(0, 200)}`);
        return (await res.json());
    }
    async buildSwap(p) {
        const qs = new URLSearchParams({
            inputMint: p.inputMint,
            outputMint: p.outputMint,
            amount: p.amount.toString(),
            slippageBps: String(p.slippageBps),
            restrictIntermediateTokens: "true",
        });
        const quote = await this.request(`/quote?${qs.toString()}`);
        if (quote.inputMint !== p.inputMint || quote.outputMint !== p.outputMint)
            throw new Error("Jupiter quote is for different tokens");
        if (quote.inAmount !== p.amount.toString())
            throw new Error("Jupiter quote input amount differs from the request");
        if (quote.swapMode && quote.swapMode !== "ExactIn")
            throw new Error("Jupiter quote is not ExactIn");
        if (Number(quote.slippageBps) > p.slippageBps)
            throw new Error("Jupiter quote slippage exceeds the request");
        const swap = await this.request("/swap", {
            method: "POST",
            body: JSON.stringify({
                quoteResponse: quote,
                userPublicKey: p.userPublicKey,
                wrapAndUnwrapSol: true,
                dynamicComputeUnitLimit: true,
            }),
        });
        if (!swap.swapTransaction)
            throw new Error("Jupiter response did not include a transaction");
        return fromBase64(swap.swapTransaction);
    }
}
//# sourceMappingURL=jupiter.js.map