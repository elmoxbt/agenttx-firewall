export function parseUnits(value, decimals) {
    const m = /^(\d+)(?:\.(\d+))?$/.exec(value.trim());
    if (!m)
        throw new Error(`Invalid decimal amount "${value}"`);
    const frac = m[2] ?? "";
    if (frac.length > decimals)
        throw new Error(`Too many decimal places in "${value}" (max ${decimals})`);
    return BigInt(m[1] + frac.padEnd(decimals, "0"));
}
export function formatUnits(v, decimals) {
    const s = v.toString().padStart(decimals + 1, "0");
    const int = s.slice(0, s.length - decimals);
    const frac = s.slice(s.length - decimals).replace(/0+$/, "");
    return frac ? `${int}.${frac}` : int;
}
//# sourceMappingURL=units.js.map