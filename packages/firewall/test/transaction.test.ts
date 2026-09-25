import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { test } from "node:test";
import { KeypairSigner, signWire } from "../src/signer.js";
import { decodeAll } from "../src/solana/decode.js";
import {
  applyLookups,
  parseLookupTableAddresses,
  parseTransaction,
  requiredSigners,
  resolveInstructions,
} from "../src/solana/transaction.js";
import { decodeBase58 } from "../src/util/base58.js";
import { concat, encodeShortVec } from "../src/util/bytes.js";
import { parseTransactionInput } from "../src/txfile.js";
import { BLOCKHASH, k, makeTx, SOL, sysTransfer, tokenApprove } from "./helpers.js";
import { SYSTEM_PROGRAM } from "../src/solana/constants.js";

test("legacy transaction compiles and parses back to the same instructions", () => {
  const self = k(1);
  const ixs = [sysTransfer(self, k(2), SOL), tokenApprove(k(3), k(4), self, 5n)];
  const tx = parseTransaction(makeTx(self, ixs));
  assert.equal(tx.version, "legacy");
  assert.deepEqual(requiredSigners(tx), [self]);
  assert.equal(tx.recentBlockhash, BLOCKHASH);
  const back = resolveInstructions(tx);
  assert.equal(back.length, 2);
  assert.equal(back[0].programId, ixs[0].programId);
  assert.deepEqual(back[0].accounts.map((a) => a.pubkey), [self, k(2)]);
  assert.deepEqual(back[0].data, ixs[0].data);
  const decoded = decodeAll(back);
  assert.equal(decoded[0].parsed.type, "sol_transfer");
  assert.equal(decoded[1].parsed.type, "token_approve");
});

test("parser rejects truncated and padded transactions", () => {
  const wire = makeTx(k(1), [sysTransfer(k(1), k(2), 1n)]);
  assert.throws(() => parseTransaction(wire.subarray(0, wire.length - 3)));
  assert.throws(() => parseTransaction(concat(wire, Uint8Array.of(0))));
});

test("v0 transaction with an address lookup table resolves loaded accounts", () => {
  const self = k(1);
  const table = k(30);
  const recipient = k(31);
  const data = concat(Uint8Array.of(2, 0, 0, 0), new Uint8Array([0x00, 0xca, 0x9a, 0x3b, 0, 0, 0, 0])); // transfer 1 SOL
  const message = concat(
    Uint8Array.of(0x80, 1, 0, 1), // v0, header
    Uint8Array.from(encodeShortVec(2)),
    decodeBase58(self),
    decodeBase58(SYSTEM_PROGRAM),
    decodeBase58(BLOCKHASH),
    Uint8Array.from(encodeShortVec(1)),
    Uint8Array.of(1, 2, 0, 2, data.length),
    data,
    Uint8Array.from(encodeShortVec(1)),
    decodeBase58(table),
    Uint8Array.of(1, 0, 0), // one writable index (0), zero readonly
  );
  const wire = concat(Uint8Array.of(1), new Uint8Array(64), message);
  const tx = parseTransaction(wire);
  assert.equal(tx.version, 0);
  assert.equal(tx.addressTableLookups.length, 1);

  const unresolved = decodeAll(resolveInstructions(tx));
  assert.ok(unresolved[0].accounts[1].pubkey.startsWith("<unresolved"));

  const tableData = concat(new Uint8Array(56), decodeBase58(recipient));
  const loaded = applyLookups(tx, new Map([[table, parseLookupTableAddresses(tableData)]]));
  const decoded = decodeAll(resolveInstructions(tx, loaded));
  assert.deepEqual(decoded[0].parsed, { type: "sol_transfer", from: self, to: recipient, lamports: 1_000_000_000n });
});

test("KeypairSigner signatures verify against the message", async () => {
  const signer = KeypairSigner.generate();
  const wire = makeTx(signer.publicKey, [sysTransfer(signer.publicKey, k(2), SOL)]);
  const signed = await signWire(wire, signer);
  const tx = parseTransaction(signed);
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(decodeBase58(signer.publicKey)).toString("base64url") }, format: "jwk" });
  assert.ok(verify(null, tx.messageBytes, key, tx.signatures[0]));
});

test("transaction JSON input: instructions format and raw base64", () => {
  const self = k(1);
  const wire = makeTx(self, [sysTransfer(self, k(2), 5n)]);
  const b64 = Buffer.from(wire).toString("base64");
  assert.deepEqual(parseTransactionInput(b64), wire);
  assert.deepEqual(parseTransactionInput(JSON.stringify({ base64: b64 })), wire);
  const ix = sysTransfer(self, k(2), 5n);
  const viaJson = parseTransactionInput(
    JSON.stringify({
      feePayer: self,
      recentBlockhash: BLOCKHASH,
      instructions: [{ programId: ix.programId, accounts: ix.accounts, data: Buffer.from(ix.data).toString("base64") }],
    }),
  );
  assert.deepEqual(viaJson, wire);
});
