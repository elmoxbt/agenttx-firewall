import { createHash } from "node:crypto";
import { ATA_PROGRAM, TOKEN_PROGRAM } from "../solana/constants.js";
import { decodeBase58, encodeBase58 } from "./base58.js";

const P = 2n ** 255n - 19n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}

function pow(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

const D = mod(-121665n * pow(121666n, P - 2n));

/**
 * True if the 32 bytes decode to a valid ed25519 curve point (i.e. could be a real public key).
 * A program-derived address must NOT be on the curve.
 */
export function isOnCurve(pub: Uint8Array): boolean {
  if (pub.length !== 32) return false;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? pub[i] & 0x7f : pub[i]);
  if (y >= P) return false;
  const y2 = (y * y) % P;
  const u = mod(y2 - 1n);
  const v = mod(D * y2 + 1n);
  const x2 = (u * pow(v, P - 2n)) % P;
  if (x2 === 0n) return true;
  return pow(x2, (P - 1n) / 2n) === 1n; // Euler's criterion: x2 is a quadratic residue
}

export function findProgramAddress(seeds: Uint8Array[], programId: string): { address: string; bump: number } {
  const pid = decodeBase58(programId);
  for (let bump = 255; bump >= 0; bump--) {
    const h = createHash("sha256");
    for (const s of seeds) h.update(s);
    h.update(Uint8Array.of(bump));
    h.update(pid);
    h.update("ProgramDerivedAddress");
    const out = new Uint8Array(h.digest());
    if (!isOnCurve(out)) return { address: encodeBase58(out), bump };
  }
  throw new Error("Unable to find a viable program address");
}

const ataCache = new Map<string, string>();

/** Associated token account address for (owner, mint, tokenProgram). */
export function deriveAta(owner: string, mint: string, tokenProgram: string = TOKEN_PROGRAM): string {
  const k = `${owner}|${mint}|${tokenProgram}`;
  const hit = ataCache.get(k);
  if (hit) return hit;
  const { address } = findProgramAddress(
    [decodeBase58(owner), decodeBase58(tokenProgram), decodeBase58(mint)],
    ATA_PROGRAM,
  );
  ataCache.set(k, address);
  return address;
}
