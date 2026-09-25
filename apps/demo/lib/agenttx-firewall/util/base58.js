const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function encodeBase58(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0)
        zeros++;
    let n = 0n;
    for (const b of bytes)
        n = (n << 8n) | BigInt(b);
    let out = "";
    while (n > 0n) {
        out = ALPHABET[Number(n % 58n)] + out;
        n /= 58n;
    }
    return "1".repeat(zeros) + out;
}
export function decodeBase58(s) {
    let n = 0n;
    for (const c of s) {
        const i = ALPHABET.indexOf(c);
        if (i < 0)
            throw new Error(`Invalid base58 character '${c}'`);
        n = n * 58n + BigInt(i);
    }
    const bytes = [];
    while (n > 0n) {
        bytes.push(Number(n & 0xffn));
        n >>= 8n;
    }
    bytes.reverse();
    let zeros = 0;
    while (zeros < s.length && s[zeros] === "1")
        zeros++;
    return Uint8Array.from([...new Array(zeros).fill(0), ...bytes]);
}
/** True if `s` is a syntactically valid Solana address (base58, 32 bytes). */
export function isAddress(s) {
    if (s.length < 32 || s.length > 44)
        return false;
    try {
        return decodeBase58(s).length === 32;
    }
    catch {
        return false;
    }
}
export function shortAddr(s) {
    return s.length > 12 ? `${s.slice(0, 4)}…${s.slice(-4)}` : s;
}
//# sourceMappingURL=base58.js.map