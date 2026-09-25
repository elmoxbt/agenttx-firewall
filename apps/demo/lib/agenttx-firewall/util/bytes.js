export function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}
export function toHex(b) {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
export function fromHex(h) {
    const clean = h.replace(/^0x/, "");
    if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean))
        throw new Error("Invalid hex string");
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
}
export function toBase64(b) {
    return Buffer.from(b).toString("base64");
}
export function fromBase64(s) {
    return new Uint8Array(Buffer.from(s, "base64"));
}
export function bytesEqual(a, b) {
    if (a.length !== b.length)
        return false;
    for (let i = 0; i < a.length; i++)
        if (a[i] !== b[i])
            return false;
    return true;
}
export function readU16(d, o) {
    return d[o] | (d[o + 1] << 8);
}
export function readU32(d, o) {
    return (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;
}
export function readU64(d, o) {
    let v = 0n;
    for (let i = 7; i >= 0; i--)
        v = (v << 8n) | BigInt(d[o + i]);
    return v;
}
export function u32le(n) {
    const b = new Uint8Array(4);
    for (let i = 0; i < 4; i++)
        b[i] = (n >>> (8 * i)) & 0xff;
    return b;
}
export function u64le(n) {
    if (n < 0n || n >= 1n << 64n)
        throw new Error("u64 out of range");
    const b = new Uint8Array(8);
    for (let i = 0; i < 8; i++)
        b[i] = Number((n >> BigInt(8 * i)) & 0xffn);
    return b;
}
/** Solana "compact-u16" length prefix. */
export function encodeShortVec(n) {
    const out = [];
    let v = n;
    for (;;) {
        const byte = v & 0x7f;
        v >>= 7;
        if (v === 0) {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}
//# sourceMappingURL=bytes.js.map