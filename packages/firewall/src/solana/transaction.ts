import { decodeBase58, encodeBase58 } from "../util/base58.js";
import { concat, encodeShortVec } from "../util/bytes.js";

export interface AccountMeta {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

export interface Instruction {
  programId: string;
  accounts: AccountMeta[];
  data: Uint8Array;
}

export interface CompiledInstruction {
  programIdIndex: number;
  accountIndexes: number[];
  data: Uint8Array;
}

export interface AddressTableLookup {
  accountKey: string;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

export interface LoadedAddresses {
  writable: string[];
  readonly: string[];
}

export interface ParsedTransaction {
  version: "legacy" | 0;
  signatures: Uint8Array[];
  header: { numRequiredSignatures: number; numReadonlySigned: number; numReadonlyUnsigned: number };
  staticAccountKeys: string[];
  recentBlockhash: string;
  compiledInstructions: CompiledInstruction[];
  addressTableLookups: AddressTableLookup[];
  messageBytes: Uint8Array;
}

class Reader {
  o = 0;
  constructor(readonly b: Uint8Array) {}
  u8(): number {
    if (this.o >= this.b.length) throw new Error("Unexpected end of transaction data");
    return this.b[this.o++];
  }
  take(n: number): Uint8Array {
    if (n < 0 || this.o + n > this.b.length) throw new Error("Unexpected end of transaction data");
    const s = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return s;
  }
  shortvec(): number {
    let v = 0;
    for (let shift = 0; shift <= 14; shift += 7) {
      const byte = this.u8();
      v |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return v;
    }
    throw new Error("Invalid compact-u16 length");
  }
}

/** Parse a serialized (wire-format) legacy or v0 transaction. Throws on any malformation. */
export function parseTransaction(wire: Uint8Array): ParsedTransaction {
  const r = new Reader(wire);
  const sigCount = r.shortvec();
  const signatures: Uint8Array[] = [];
  for (let i = 0; i < sigCount; i++) signatures.push(new Uint8Array(r.take(64)));

  const msgStart = r.o;
  let version: "legacy" | 0 = "legacy";
  let first = r.u8();
  if (first & 0x80) {
    const v = first & 0x7f;
    if (v !== 0) throw new Error(`Unsupported transaction version ${v}`);
    version = 0;
    first = r.u8();
  }
  const header = { numRequiredSignatures: first, numReadonlySigned: r.u8(), numReadonlyUnsigned: r.u8() };

  const nKeys = r.shortvec();
  const staticAccountKeys: string[] = [];
  for (let i = 0; i < nKeys; i++) staticAccountKeys.push(encodeBase58(r.take(32)));
  const recentBlockhash = encodeBase58(r.take(32));

  const nIx = r.shortvec();
  const compiledInstructions: CompiledInstruction[] = [];
  for (let i = 0; i < nIx; i++) {
    const programIdIndex = r.u8();
    const nAcc = r.shortvec();
    const accountIndexes: number[] = [];
    for (let j = 0; j < nAcc; j++) accountIndexes.push(r.u8());
    const dataLen = r.shortvec();
    compiledInstructions.push({ programIdIndex, accountIndexes, data: new Uint8Array(r.take(dataLen)) });
  }

  const addressTableLookups: AddressTableLookup[] = [];
  if (version === 0) {
    const nLookups = r.shortvec();
    for (let i = 0; i < nLookups; i++) {
      const accountKey = encodeBase58(r.take(32));
      const nw = r.shortvec();
      const writableIndexes = Array.from(r.take(nw));
      const nr = r.shortvec();
      const readonlyIndexes = Array.from(r.take(nr));
      addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes });
    }
  }

  if (r.o !== wire.length) throw new Error(`Trailing bytes after transaction message (${wire.length - r.o})`);
  if (signatures.length !== header.numRequiredSignatures) {
    throw new Error(
      `Signature count (${signatures.length}) does not match required signatures (${header.numRequiredSignatures})`,
    );
  }
  if (header.numRequiredSignatures === 0 || header.numRequiredSignatures > nKeys) {
    throw new Error("Invalid message header");
  }
  return {
    version,
    signatures,
    header,
    staticAccountKeys,
    recentBlockhash,
    compiledInstructions,
    addressTableLookups,
    messageBytes: wire.subarray(msgStart),
  };
}

export function requiredSigners(tx: ParsedTransaction): string[] {
  return tx.staticAccountKeys.slice(0, tx.header.numRequiredSignatures);
}

/** Expand compiled instructions into full account metas. Unresolved lookup accounts get placeholder keys. */
export function resolveInstructions(tx: ParsedTransaction, loaded?: LoadedAddresses): Instruction[] {
  const nStatic = tx.staticAccountKeys.length;
  const totalW = tx.addressTableLookups.reduce((n, l) => n + l.writableIndexes.length, 0);
  const totalR = tx.addressTableLookups.reduce((n, l) => n + l.readonlyIndexes.length, 0);
  const writable = loaded?.writable ?? Array.from({ length: totalW }, (_, i) => `<unresolved-w${i}>`);
  const readonly = loaded?.readonly ?? Array.from({ length: totalR }, (_, i) => `<unresolved-r${i}>`);
  const keys = [...tx.staticAccountKeys, ...writable, ...readonly];
  const { numRequiredSignatures: nSig, numReadonlySigned, numReadonlyUnsigned } = tx.header;

  const meta = (idx: number) => {
    if (idx >= keys.length) throw new Error(`Account index ${idx} is out of range`);
    let isSigner = false;
    let isWritable = false;
    if (idx < nStatic) {
      isSigner = idx < nSig;
      isWritable = isSigner ? idx < nSig - numReadonlySigned : idx < nStatic - numReadonlyUnsigned;
    } else {
      isWritable = idx - nStatic < writable.length;
    }
    return { pubkey: keys[idx], isSigner, isWritable };
  };

  return tx.compiledInstructions.map((ci) => {
    if (ci.programIdIndex >= keys.length) throw new Error(`Program index ${ci.programIdIndex} is out of range`);
    return { programId: keys[ci.programIdIndex], accounts: ci.accountIndexes.map(meta), data: ci.data };
  });
}

export function hasLookups(tx: ParsedTransaction): boolean {
  return tx.addressTableLookups.length > 0;
}

/** Address lookup table account layout: 56-byte header followed by 32-byte addresses. */
export function parseLookupTableAddresses(data: Uint8Array): string[] {
  const META = 56;
  if (data.length < META || (data.length - META) % 32 !== 0) throw new Error("Malformed address lookup table account");
  const out: string[] = [];
  for (let o = META; o < data.length; o += 32) out.push(encodeBase58(data.subarray(o, o + 32)));
  return out;
}

export function applyLookups(tx: ParsedTransaction, tables: Map<string, string[]>): LoadedAddresses {
  const writable: string[] = [];
  const readonly: string[] = [];
  for (const l of tx.addressTableLookups) {
    const addrs = tables.get(l.accountKey);
    if (!addrs) throw new Error(`Lookup table ${l.accountKey} was not provided`);
    for (const i of l.writableIndexes) {
      if (i >= addrs.length) throw new Error(`Lookup index ${i} out of range for table ${l.accountKey}`);
      writable.push(addrs[i]);
    }
    for (const i of l.readonlyIndexes) {
      if (i >= addrs.length) throw new Error(`Lookup index ${i} out of range for table ${l.accountKey}`);
      readonly.push(addrs[i]);
    }
  }
  return { writable, readonly };
}

/** Compile a legacy message. Account ordering follows the Solana runtime rules. */
export function compileLegacyMessage(
  feePayer: string,
  recentBlockhash: string,
  instructions: Instruction[],
): Uint8Array {
  interface M {
    pubkey: string;
    signer: boolean;
    writable: boolean;
  }
  const map = new Map<string, M>();
  const add = (pubkey: string, signer: boolean, writable: boolean) => {
    const e = map.get(pubkey);
    if (e) {
      e.signer ||= signer;
      e.writable ||= writable;
    } else map.set(pubkey, { pubkey, signer, writable });
  };
  add(feePayer, true, true);
  for (const ix of instructions) {
    for (const a of ix.accounts) add(a.pubkey, a.isSigner, a.isWritable);
    add(ix.programId, false, false);
  }
  const feeM = map.get(feePayer)!;
  const rest = [...map.values()].filter((m) => m !== feeM);
  const sw = [feeM, ...rest.filter((m) => m.signer && m.writable)];
  const sr = rest.filter((m) => m.signer && !m.writable);
  const nw = rest.filter((m) => !m.signer && m.writable);
  const nr = rest.filter((m) => !m.signer && !m.writable);
  const ordered = [...sw, ...sr, ...nw, ...nr];
  if (ordered.length > 256) throw new Error("Too many accounts for a legacy transaction");
  const index = new Map(ordered.map((m, i) => [m.pubkey, i]));

  const bh = decodeBase58(recentBlockhash);
  if (bh.length !== 32) throw new Error("Invalid recent blockhash");

  const parts: Uint8Array[] = [
    Uint8Array.of(sw.length + sr.length, sr.length, nr.length),
    Uint8Array.from(encodeShortVec(ordered.length)),
    ...ordered.map((m) => decodeBase58(m.pubkey)),
    bh,
    Uint8Array.from(encodeShortVec(instructions.length)),
  ];
  for (const ix of instructions) {
    parts.push(
      Uint8Array.of(index.get(ix.programId)!),
      Uint8Array.from(encodeShortVec(ix.accounts.length)),
      Uint8Array.from(ix.accounts.map((a) => index.get(a.pubkey)!)),
      Uint8Array.from(encodeShortVec(ix.data.length)),
      ix.data,
    );
  }
  return concat(...parts);
}

/** Wire-format transaction with all-zero signature placeholders. */
export function unsignedWire(message: Uint8Array): Uint8Array {
  const isV0 = (message[0] & 0x80) !== 0;
  const numSigs = message[isV0 ? 1 : 0];
  return concat(Uint8Array.from(encodeShortVec(numSigs)), new Uint8Array(64 * numSigs), message);
}

export function withSignature(wire: Uint8Array, signerIndex: number, signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) throw new Error("Signature must be 64 bytes");
  const tx = parseTransaction(wire);
  const sigs = tx.signatures.map((s, i) => (i === signerIndex ? signature : s));
  return concat(Uint8Array.from(encodeShortVec(sigs.length)), ...sigs, tx.messageBytes);
}
