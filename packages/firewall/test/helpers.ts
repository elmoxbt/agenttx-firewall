import { encodeBase58 } from "../src/util/base58.js";
import { concat, fromHex, u32le, u64le } from "../src/util/bytes.js";
import { deriveAta } from "../src/util/pda.js";
import {
  ATA_PROGRAM,
  COMPUTE_BUDGET_PROGRAM,
  JUPITER_V6_PROGRAM,
  SYSTEM_PROGRAM,
  TOKEN_PROGRAM,
  USDC_MINT,
  WSOL_MINT,
} from "../src/solana/constants.js";
import { anchorDiscriminator } from "../src/solana/decode.js";
import { compileLegacyMessage, unsignedWire, type Instruction } from "../src/solana/transaction.js";
import type { AccountInfo, Rpc, SimulationResult } from "../src/solana/rpc.js";

/** Deterministic dummy address. */
export const k = (n: number): string => encodeBase58(new Uint8Array(32).fill(n));
export const BLOCKHASH = k(9);
export const SOL = 1_000_000_000n;

const signer = (pubkey: string, writable = true) => ({ pubkey, isSigner: true, isWritable: writable });
const w = (pubkey: string) => ({ pubkey, isSigner: false, isWritable: true });
const r = (pubkey: string) => ({ pubkey, isSigner: false, isWritable: false });

export const sysTransfer = (from: string, to: string, lamports: bigint): Instruction => ({
  programId: SYSTEM_PROGRAM,
  accounts: [signer(from), w(to)],
  data: concat(u32le(2), u64le(lamports)),
});

export const computeLimit = (units: number): Instruction => ({
  programId: COMPUTE_BUDGET_PROGRAM,
  accounts: [],
  data: concat(Uint8Array.of(2), u32le(units)),
});

export const computePrice = (micro: bigint): Instruction => ({
  programId: COMPUTE_BUDGET_PROGRAM,
  accounts: [],
  data: concat(Uint8Array.of(3), u64le(micro)),
});

export const tokenApprove = (source: string, delegate: string, owner: string, amount: bigint): Instruction => ({
  programId: TOKEN_PROGRAM,
  accounts: [w(source), r(delegate), signer(owner, false)],
  data: concat(Uint8Array.of(4), u64le(amount)),
});

export const tokenSetAuthority = (account: string, current: string, newAuthority: string): Instruction => ({
  programId: TOKEN_PROGRAM,
  accounts: [w(account), signer(current, false)],
  data: concat(Uint8Array.of(6, 2, 1), Uint8Array.from(atob58(newAuthority))),
});

const atob58 = (s: string): Uint8Array => {
  // tiny local decode via the library to avoid duplicate logic in tests
  return decode(s);
};
import { decodeBase58 as decode } from "../src/util/base58.js";

export const tokenTransferChecked = (source: string, mint: string, dest: string, owner: string, amount: bigint, decimals: number): Instruction => ({
  programId: TOKEN_PROGRAM,
  accounts: [w(source), r(mint), w(dest), signer(owner, false)],
  data: concat(Uint8Array.of(12), u64le(amount), Uint8Array.of(decimals)),
});

export const syncNative = (account: string): Instruction => ({ programId: TOKEN_PROGRAM, accounts: [w(account)], data: Uint8Array.of(17) });

export const closeAccount = (account: string, dest: string, owner: string): Instruction => ({
  programId: TOKEN_PROGRAM,
  accounts: [w(account), w(dest), signer(owner, false)],
  data: Uint8Array.of(9),
});

export const ataCreate = (payer: string, owner: string, mint: string): Instruction => ({
  programId: ATA_PROGRAM,
  accounts: [signer(payer), w(deriveAta(owner, mint)), r(owner), r(mint), r(SYSTEM_PROGRAM), r(TOKEN_PROGRAM)],
  data: Uint8Array.of(1),
});

export function jupiterShared(o: {
  self: string;
  sourceMint: string;
  destMint: string;
  destAccount: string;
  amount: bigint;
  out?: bigint;
  slippageBps?: number;
  feeBps?: number;
  name?: string;
}): Instruction {
  const slip = o.slippageBps ?? 50;
  const data = concat(
    fromHex(anchorDiscriminator(o.name ?? "shared_accounts_route")),
    Uint8Array.of(1), // id
    u32le(0), // empty route plan
    u64le(o.amount),
    u64le(o.out ?? 1_000_000n),
    Uint8Array.of(slip & 0xff, slip >> 8),
    Uint8Array.of(o.feeBps ?? 0),
  );
  return {
    programId: JUPITER_V6_PROGRAM,
    accounts: [
      r(TOKEN_PROGRAM),
      r(k(50)),
      signer(o.self, false),
      w(deriveAta(o.self, o.sourceMint)),
      w(k(51)),
      w(k(52)),
      w(o.destAccount),
      r(o.sourceMint),
      r(o.destMint),
      r(JUPITER_V6_PROGRAM),
      r(k(53)),
    ],
    data,
  };
}

/** A swap transaction shaped like Jupiter's output: wrap SOL, route, unwrap. */
export function jupiterSwapTx(self: string, opts: { lamports?: bigint; destAccount?: string; slippageBps?: number; routeAmount?: bigint; feeBps?: number } = {}): Uint8Array {
  const lamports = opts.lamports ?? SOL / 5n;
  const wsolAta = deriveAta(self, WSOL_MINT);
  const usdcAta = deriveAta(self, USDC_MINT);
  return makeTx(self, [
    computeLimit(300_000),
    computePrice(1000n),
    ataCreate(self, self, WSOL_MINT),
    ataCreate(self, self, USDC_MINT),
    sysTransfer(self, wsolAta, lamports),
    syncNative(wsolAta),
    jupiterShared({
      self,
      sourceMint: WSOL_MINT,
      destMint: USDC_MINT,
      destAccount: opts.destAccount ?? usdcAta,
      amount: opts.routeAmount ?? lamports,
      slippageBps: opts.slippageBps,
      feeBps: opts.feeBps,
    }),
    closeAccount(wsolAta, self, self),
  ]);
}

export const makeTx = (feePayer: string, ixs: Instruction[]): Uint8Array =>
  unsignedWire(compileLegacyMessage(feePayer, BLOCKHASH, ixs));

export interface MockRpcOptions {
  balance?: bigint;
  simulate?: (wire: Uint8Array) => SimulationResult;
  accounts?: Record<string, AccountInfo>;
}

export class MockRpc implements Rpc {
  sent: Uint8Array[] = [];
  constructor(private readonly opts: MockRpcOptions = {}) {}
  async getLatestBlockhash() {
    return { blockhash: BLOCKHASH, lastValidBlockHeight: 1 };
  }
  async getAccountInfo(address: string): Promise<AccountInfo | null> {
    return this.opts.accounts?.[address] ?? null;
  }
  async getBalance(): Promise<bigint> {
    return this.opts.balance ?? 10n * SOL;
  }
  async simulateTransaction(wire: Uint8Array, o: { accounts: string[] }): Promise<SimulationResult> {
    if (this.opts.simulate) return this.opts.simulate(wire);
    return { err: null, logs: [], unitsConsumed: 5000, accounts: o.accounts.map(() => ({ lamports: (this.opts.balance ?? 10n * SOL) - SOL / 5n })) };
  }
  async sendTransaction(wire: Uint8Array): Promise<string> {
    this.sent.push(wire);
    return "5mockSignature";
  }
}

export const usdcMintAccount = (): AccountInfo => {
  const data = new Uint8Array(82);
  data[44] = 6;
  return { lamports: 1n, owner: TOKEN_PROGRAM, data };
};
