import { createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { encodeBase58 } from "./util/base58.js";
import { fromBase64 } from "./util/bytes.js";
import { parseTransaction, withSignature } from "./solana/transaction.js";
const PKCS8_ED25519_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
/** Local ed25519 keypair using node:crypto. Fine for devnet and tests; use a proper KMS/HSM in production. */
export class KeypairSigner {
    publicKey;
    key;
    constructor(seed) {
        const der = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
        der.set(PKCS8_ED25519_PREFIX);
        der.set(seed, PKCS8_ED25519_PREFIX.length);
        this.key = createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" });
        const jwk = createPublicKey(this.key).export({ format: "jwk" });
        this.publicKey = encodeBase58(new Uint8Array(Buffer.from(jwk.x, "base64url")));
    }
    static generate() {
        return new KeypairSigner(new Uint8Array(randomBytes(32)));
    }
    /** Accepts a 32-byte seed or a 64-byte Solana secret key (seed || public key). */
    static fromSecretKey(bytes) {
        if (bytes.length !== 32 && bytes.length !== 64)
            throw new Error("Secret key must be 32 or 64 bytes");
        const s = new KeypairSigner(bytes.slice(0, 32));
        if (bytes.length === 64 && encodeBase58(bytes.slice(32)) !== s.publicKey)
            throw new Error("Secret key does not match its public key");
        return s;
    }
    /** Load a `solana-keygen` JSON keypair file. */
    static fromFile(path) {
        return KeypairSigner.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, "utf8"))));
    }
    async signMessage(message) {
        return new Uint8Array(sign(null, Buffer.from(message), this.key));
    }
}
export async function signWire(wire, signer) {
    const tx = parseTransaction(wire);
    const idx = tx.staticAccountKeys.slice(0, tx.header.numRequiredSignatures).indexOf(signer.publicKey);
    if (idx < 0)
        throw new Error("Signer is not a required signer of this transaction");
    return withSignature(wire, idx, await signer.signMessage(tx.messageBytes));
}
export class FirewallBlockedError extends Error {
    report;
    constructor(report) {
        super(`AgentTx Firewall ${report.verdict === "BLOCK" ? "blocked" : "held for review"} the transaction: ${report.reasons.join("; ") || "review required"}`);
        this.report = report;
        this.name = "FirewallBlockedError";
    }
}
/**
 * Drop-in replacement for a signer handed to an agent. It has no raw `signMessage`:
 * the only way to get a signature is through the firewall.
 */
export class GuardedSigner {
    inner;
    firewall;
    opts;
    constructor(inner, firewall, opts = {}) {
        this.inner = inner;
        this.firewall = firewall;
        this.opts = opts;
    }
    get publicKey() {
        return this.inner.publicKey;
    }
    async signTransaction(tx, inspect = {}) {
        const wire = typeof tx === "string" ? fromBase64(tx) : tx;
        const report = await this.firewall.inspect(wire, { ...inspect, self: this.inner.publicKey });
        if (report.verdict === "BLOCK" || (report.verdict === "REVIEW" && !this.opts.allowReview)) {
            throw new FirewallBlockedError(report);
        }
        return { wire: await signWire(wire, this.inner), report };
    }
}
//# sourceMappingURL=signer.js.map