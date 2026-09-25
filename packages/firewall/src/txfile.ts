import { isAddress } from "./util/base58.js";
import { fromBase64, fromHex, toBase64 } from "./util/bytes.js";
import { compileLegacyMessage, unsignedWire, type Instruction } from "./solana/transaction.js";

interface JsonInstruction {
  programId: string;
  accounts: { pubkey: string; isSigner?: boolean; isWritable?: boolean }[];
  data?: string;
  dataHex?: string;
}

/**
 * Accepts any of:
 *  - a raw base64 wire-format transaction
 *  - {"base64": "..."} (also "transaction" / "swapTransaction")
 *  - {"feePayer", "recentBlockhash"?, "instructions": [{programId, accounts[], data(base64) | dataHex}]}
 */
export function parseTransactionInput(text: string): Uint8Array {
  const t = text.trim();
  if (!t.startsWith("{")) return fromBase64(t);
  const j = JSON.parse(t) as Record<string, unknown>;
  const b64 = j.base64 ?? j.transaction ?? j.swapTransaction;
  if (typeof b64 === "string") return fromBase64(b64);
  if (Array.isArray(j.instructions)) {
    const feePayer = j.feePayer;
    if (typeof feePayer !== "string" || !isAddress(feePayer)) throw new Error('"feePayer" must be a valid address');
    const instructions: Instruction[] = (j.instructions as JsonInstruction[]).map((ix, i) => {
      if (!ix.programId || !isAddress(ix.programId)) throw new Error(`instructions[${i}].programId is invalid`);
      const data = ix.dataHex !== undefined ? fromHex(ix.dataHex) : fromBase64(ix.data ?? "");
      return {
        programId: ix.programId,
        accounts: (ix.accounts ?? []).map((a) => ({ pubkey: a.pubkey, isSigner: !!a.isSigner, isWritable: !!a.isWritable })),
        data,
      };
    });
    const blockhash = typeof j.recentBlockhash === "string" ? j.recentBlockhash : "11111111111111111111111111111111";
    return unsignedWire(compileLegacyMessage(feePayer, blockhash, instructions));
  }
  throw new Error('Unrecognised transaction JSON: expected "base64" or "instructions"');
}

export function toTransactionJson(wire: Uint8Array): string {
  return JSON.stringify({ base64: toBase64(wire) }, null, 2);
}
