import { resolveAsset } from "./policy/policy.js";
import { ATA_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAMS, TOKEN_PROGRAM } from "./solana/constants.js";
import { compileLegacyMessage, unsignedWire } from "./solana/transaction.js";
import { concat, u32le, u64le } from "./util/bytes.js";
import { decodeBase58 } from "./util/base58.js";
import { deriveAta } from "./util/pda.js";
import { parseUnits } from "./util/units.js";
export class BuildError extends Error {
}
export async function buildTransfer(intent, policy, self, rpc) {
    const asset = resolveAsset(policy, intent.asset);
    if (!asset)
        throw new BuildError(`Asset ${intent.asset} is not allowlisted`);
    const amount = parseUnits(intent.amount, asset.decimals);
    if (amount === 0n)
        throw new BuildError("Amount must be greater than zero");
    const { blockhash } = await rpc.getLatestBlockhash();
    const instructions = [];
    if (asset.native) {
        instructions.push({
            programId: SYSTEM_PROGRAM,
            accounts: [
                { pubkey: self, isSigner: true, isWritable: true },
                { pubkey: intent.to, isSigner: false, isWritable: true },
            ],
            data: concat(u32le(2), u64le(amount)),
        });
    }
    else {
        let tokenProgram = TOKEN_PROGRAM;
        const mintInfo = await rpc.getAccountInfo(asset.mint);
        if (mintInfo) {
            if (!TOKEN_PROGRAMS.includes(mintInfo.owner))
                throw new BuildError(`${asset.mint} is not a token mint`);
            tokenProgram = mintInfo.owner;
            if (mintInfo.data.length > 44 && mintInfo.data[44] !== asset.decimals) {
                throw new BuildError(`On-chain decimals (${mintInfo.data[44]}) differ from policy (${asset.decimals}) for ${asset.symbol}`);
            }
        }
        const source = deriveAta(self, asset.mint, tokenProgram);
        const dest = deriveAta(intent.to, asset.mint, tokenProgram);
        instructions.push({
            programId: ATA_PROGRAM,
            accounts: [
                { pubkey: self, isSigner: true, isWritable: true },
                { pubkey: dest, isSigner: false, isWritable: true },
                { pubkey: intent.to, isSigner: false, isWritable: false },
                { pubkey: asset.mint, isSigner: false, isWritable: false },
                { pubkey: SYSTEM_PROGRAM, isSigner: false, isWritable: false },
                { pubkey: tokenProgram, isSigner: false, isWritable: false },
            ],
            data: Uint8Array.of(1),
        });
        instructions.push({
            programId: tokenProgram,
            accounts: [
                { pubkey: source, isSigner: false, isWritable: true },
                { pubkey: asset.mint, isSigner: false, isWritable: false },
                { pubkey: dest, isSigner: false, isWritable: true },
                { pubkey: self, isSigner: true, isWritable: false },
            ],
            data: concat(Uint8Array.of(12), u64le(amount), Uint8Array.of(asset.decimals)),
        });
    }
    decodeBase58(self); // throws on invalid signer address
    return unsignedWire(compileLegacyMessage(self, blockhash, instructions));
}
export async function buildSwap(intent, policy, self, provider) {
    const inp = resolveAsset(policy, intent.input);
    const out = resolveAsset(policy, intent.output);
    if (!inp || !out)
        throw new BuildError("Swap asset is not allowlisted");
    const amount = parseUnits(intent.amount, inp.decimals);
    if (amount === 0n)
        throw new BuildError("Amount must be greater than zero");
    const slippageBps = intent.slippageBps ?? Math.min(50, policy.limits.maxSlippageBps);
    return provider.buildSwap({ inputMint: inp.mint, outputMint: out.mint, amount, slippageBps, userPublicKey: self });
}
//# sourceMappingURL=builder.js.map