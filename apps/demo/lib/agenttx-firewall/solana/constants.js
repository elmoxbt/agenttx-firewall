export const SYSTEM_PROGRAM = "11111111111111111111111111111111";
export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
export const ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
export const COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111";
export const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
export const MEMO_V1_PROGRAM = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
export const JUPITER_V6_PROGRAM = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";
export const WSOL_MINT = "So11111111111111111111111111111111111111112";
export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
export const USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
export const USDC_DEVNET_MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
export const TOKEN_PROGRAMS = [TOKEN_PROGRAM, TOKEN_2022_PROGRAM];
export const LAMPORTS_PER_SOL = 1000000000n;
/** Rent for a standard 165-byte token account; used only for estimates in reports. */
export const ATA_RENT_LAMPORTS = 2039280n;
export const PROGRAM_LABELS = {
    [SYSTEM_PROGRAM]: "System Program",
    [TOKEN_PROGRAM]: "SPL Token",
    [TOKEN_2022_PROGRAM]: "Token-2022",
    [ATA_PROGRAM]: "Associated Token Account",
    [COMPUTE_BUDGET_PROGRAM]: "Compute Budget",
    [MEMO_PROGRAM]: "Memo",
    [MEMO_V1_PROGRAM]: "Memo v1",
    [JUPITER_V6_PROGRAM]: "Jupiter",
};
/** Programs that are plumbing rather than the "application" a transaction talks to. */
export const INFRA_PROGRAMS = new Set([
    SYSTEM_PROGRAM,
    TOKEN_PROGRAM,
    TOKEN_2022_PROGRAM,
    ATA_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    MEMO_V1_PROGRAM,
]);
const ALL = ["mainnet-beta", "devnet", "testnet", "localnet"];
export const KNOWN_TOKENS = [
    { symbol: "SOL", mint: WSOL_MINT, decimals: 9, clusters: ALL },
    { symbol: "USDC", mint: USDC_MINT, decimals: 6, clusters: ["mainnet-beta"] },
    { symbol: "USDT", mint: USDT_MINT, decimals: 6, clusters: ["mainnet-beta"] },
    { symbol: "USDC", mint: USDC_DEVNET_MINT, decimals: 6, clusters: ["devnet"] },
];
export const CLUSTER_RPC = {
    "mainnet-beta": "https://api.mainnet-beta.solana.com",
    devnet: "https://api.devnet.solana.com",
    testnet: "https://api.testnet.solana.com",
    localnet: "http://127.0.0.1:8899",
};
//# sourceMappingURL=constants.js.map