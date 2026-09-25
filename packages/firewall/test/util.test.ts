import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import * as C from "../src/solana/constants.js";
import { anchorDiscriminator } from "../src/solana/decode.js";
import { decodeBase58, encodeBase58, isAddress } from "../src/util/base58.js";
import { deriveAta, isOnCurve } from "../src/util/pda.js";
import { formatUnits, parseUnits } from "../src/util/units.js";

test("base58 round-trips, including leading zeros", () => {
  for (const bytes of [new Uint8Array(32), new Uint8Array(32).fill(255), Uint8Array.of(0, 0, 1, 2, 3)]) {
    assert.deepEqual(decodeBase58(encodeBase58(bytes)), bytes);
  }
  assert.equal(encodeBase58(new Uint8Array(32)), "11111111111111111111111111111111");
});

test("built-in program and mint constants are valid 32-byte addresses", () => {
  for (const [name, value] of Object.entries(C)) {
    if (typeof value === "string" && /PROGRAM|MINT/.test(name)) assert.ok(isAddress(value), name);
  }
});

test("isOnCurve accepts real ed25519 public keys", () => {
  for (let i = 0; i < 40; i++) {
    const { publicKey } = generateKeyPairSync("ed25519");
    const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
    assert.ok(isOnCurve(new Uint8Array(Buffer.from(x, "base64url"))));
  }
});

test("derived token accounts are off-curve and deterministic", () => {
  const owner = encodeBase58(new Uint8Array(32).fill(7));
  const ata = deriveAta(owner, C.USDC_MINT);
  assert.equal(ata, deriveAta(owner, C.USDC_MINT));
  assert.ok(!isOnCurve(decodeBase58(ata)));
  assert.notEqual(ata, deriveAta(owner, C.WSOL_MINT));
});

test("Anchor discriminators match Jupiter's published values", () => {
  assert.equal(anchorDiscriminator("route"), "e517cb977ae3ad2a");
  assert.equal(anchorDiscriminator("shared_accounts_route"), "c1209b3341d69c81");
});

test("decimal parsing and formatting", () => {
  assert.equal(parseUnits("0.2", 9), 200_000_000n);
  assert.equal(formatUnits(200_000_000n, 9), "0.2");
  assert.equal(formatUnits(5n, 0), "5");
  assert.throws(() => parseUnits("1.0000000001", 9));
  assert.throws(() => parseUnits("1e5", 9));
});
