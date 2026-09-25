import { createHash } from "node:crypto";
import { encodeBase58, shortAddr } from "../util/base58.js";
import { readU16, readU32, readU64, toHex } from "../util/bytes.js";
import { formatUnits } from "../util/units.js";
import { ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, JUPITER_V6_PROGRAM, MEMO_PROGRAM, MEMO_V1_PROGRAM, PROGRAM_LABELS, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, } from "./constants.js";
class Malformed extends Error {
}
function need(ix, minData, minAccounts) {
    if (ix.data.length < minData)
        throw new Malformed(`data too short (${ix.data.length} < ${minData})`);
    if (ix.accounts.length < minAccounts) {
        throw new Malformed(`expected at least ${minAccounts} accounts, got ${ix.accounts.length}`);
    }
}
const acc = (ix, i) => ix.accounts[i].pubkey;
const pk = (d, o) => encodeBase58(d.subarray(o, o + 32));
/** Anchor discriminator: first 8 bytes of sha256("global:<snake_case_name>"), hex-encoded. */
export function anchorDiscriminator(name) {
    return toHex(new Uint8Array(createHash("sha256").update(`global:${name}`).digest()).subarray(0, 8));
}
// ---------------------------------------------------------------------------------------------
// System program
// ---------------------------------------------------------------------------------------------
function decodeSystem(ix) {
    need(ix, 4, 0);
    const d = ix.data;
    const kind = readU32(d, 0);
    switch (kind) {
        case 0:
            need(ix, 52, 2);
            return {
                name: "create_account",
                parsed: {
                    type: "sol_create_account",
                    from: acc(ix, 0),
                    newAccount: acc(ix, 1),
                    lamports: readU64(d, 4),
                    space: readU64(d, 12),
                    owner: pk(d, 20),
                },
            };
        case 1:
            need(ix, 36, 1);
            return { name: "assign", parsed: { type: "assign", account: acc(ix, 0), owner: pk(d, 4) } };
        case 2:
            need(ix, 12, 2);
            return {
                name: "transfer",
                parsed: { type: "sol_transfer", from: acc(ix, 0), to: acc(ix, 1), lamports: readU64(d, 4) },
            };
        case 3: {
            need(ix, 44, 2);
            const seedLen = Number(readU64(d, 36));
            if (seedLen > 32)
                throw new Malformed("seed too long");
            const o = 44 + seedLen;
            need(ix, o + 48, 2);
            return {
                name: "create_account_with_seed",
                parsed: {
                    type: "sol_create_account",
                    from: acc(ix, 0),
                    newAccount: acc(ix, 1),
                    lamports: readU64(d, o),
                    space: readU64(d, o + 8),
                    owner: pk(d, o + 16),
                },
            };
        }
        case 4:
            return { name: "advance_nonce_account", parsed: { type: "other" } };
        case 5:
            need(ix, 12, 2);
            return {
                name: "withdraw_nonce_account",
                parsed: { type: "sol_transfer", from: acc(ix, 0), to: acc(ix, 1), lamports: readU64(d, 4) },
            };
        case 6:
            return { name: "initialize_nonce_account", parsed: { type: "other" } };
        case 7:
            need(ix, 36, 2);
            return {
                name: "authorize_nonce_account",
                parsed: {
                    type: "authority_change",
                    target: acc(ix, 0),
                    kind: "nonce",
                    newAuthority: pk(d, 4),
                    currentAuthority: acc(ix, 1),
                },
            };
        case 8:
            return { name: "allocate", parsed: { type: "other" } };
        case 9:
            return { name: "allocate_with_seed", parsed: { type: "other" } };
        case 10: {
            need(ix, 44, 1);
            const seedLen = Number(readU64(d, 36));
            if (seedLen > 32)
                throw new Malformed("seed too long");
            need(ix, 44 + seedLen + 32, 1);
            return { name: "assign_with_seed", parsed: { type: "assign", account: acc(ix, 0), owner: pk(d, 44 + seedLen) } };
        }
        case 11:
            need(ix, 12, 3);
            return {
                name: "transfer_with_seed",
                parsed: { type: "sol_transfer", from: acc(ix, 0), to: acc(ix, 2), lamports: readU64(d, 4) },
            };
        case 12:
            return { name: "upgrade_nonce_account", parsed: { type: "other" } };
        default:
            return { name: `unknown_${kind}`, parsed: { type: "opaque" } };
    }
}
// ---------------------------------------------------------------------------------------------
// SPL Token / Token-2022 (shared base instruction set)
// ---------------------------------------------------------------------------------------------
const AUTHORITY_TYPES = [
    "MintTokens",
    "FreezeAccount",
    "AccountOwner",
    "CloseAccount",
    "TransferFeeConfig",
    "WithheldWithdraw",
    "CloseMint",
    "InterestRate",
    "PermanentDelegate",
    "ConfidentialTransferMint",
    "TransferHookProgramId",
    "ConfidentialTransferFeeConfig",
    "MetadataPointer",
    "GroupPointer",
    "GroupMemberPointer",
];
function decodeToken(ix) {
    need(ix, 1, 0);
    const d = ix.data;
    switch (d[0]) {
        case 0:
            return { name: "initialize_mint", parsed: { type: "other" } };
        case 1:
            return { name: "initialize_account", parsed: { type: "other" } };
        case 2:
            return { name: "initialize_multisig", parsed: { type: "other" } };
        case 3:
            need(ix, 9, 3);
            return {
                name: "transfer",
                parsed: { type: "token_transfer", source: acc(ix, 0), destination: acc(ix, 1), authority: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 4:
            need(ix, 9, 3);
            return {
                name: "approve",
                parsed: { type: "token_approve", source: acc(ix, 0), delegate: acc(ix, 1), owner: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 5:
            need(ix, 1, 2);
            return { name: "revoke", parsed: { type: "token_revoke", source: acc(ix, 0), owner: acc(ix, 1) } };
        case 6: {
            need(ix, 3, 2);
            const kind = AUTHORITY_TYPES[d[1]] ?? `Type${d[1]}`;
            let newAuthority = null;
            if (d[2] === 1) {
                need(ix, 35, 2);
                newAuthority = pk(d, 3);
            }
            return {
                name: "set_authority",
                parsed: { type: "authority_change", target: acc(ix, 0), kind, newAuthority, currentAuthority: acc(ix, 1) },
            };
        }
        case 7:
            need(ix, 9, 3);
            return {
                name: "mint_to",
                parsed: { type: "token_mint", mint: acc(ix, 0), destination: acc(ix, 1), authority: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 8:
            need(ix, 9, 3);
            return {
                name: "burn",
                parsed: { type: "token_burn", account: acc(ix, 0), authority: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 9:
            need(ix, 1, 3);
            return {
                name: "close_account",
                parsed: { type: "token_close", account: acc(ix, 0), destination: acc(ix, 1), owner: acc(ix, 2) },
            };
        case 10:
            return { name: "freeze_account", parsed: { type: "other" } };
        case 11:
            return { name: "thaw_account", parsed: { type: "other" } };
        case 12:
            need(ix, 10, 4);
            return {
                name: "transfer_checked",
                parsed: {
                    type: "token_transfer",
                    source: acc(ix, 0),
                    mint: acc(ix, 1),
                    destination: acc(ix, 2),
                    authority: acc(ix, 3),
                    amount: readU64(d, 1),
                    decimals: d[9],
                },
            };
        case 13:
            need(ix, 10, 4);
            return {
                name: "approve_checked",
                parsed: {
                    type: "token_approve",
                    source: acc(ix, 0),
                    mint: acc(ix, 1),
                    delegate: acc(ix, 2),
                    owner: acc(ix, 3),
                    amount: readU64(d, 1),
                    decimals: d[9],
                },
            };
        case 14:
            need(ix, 10, 3);
            return {
                name: "mint_to_checked",
                parsed: { type: "token_mint", mint: acc(ix, 0), destination: acc(ix, 1), authority: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 15:
            need(ix, 10, 3);
            return {
                name: "burn_checked",
                parsed: { type: "token_burn", account: acc(ix, 0), authority: acc(ix, 2), amount: readU64(d, 1) },
            };
        case 16:
            return { name: "initialize_account2", parsed: { type: "other" } };
        case 17:
            need(ix, 1, 1);
            return { name: "sync_native", parsed: { type: "token_sync_native", account: acc(ix, 0) } };
        case 18:
            return { name: "initialize_account3", parsed: { type: "other" } };
        case 19:
            return { name: "initialize_multisig2", parsed: { type: "other" } };
        case 20:
            return { name: "initialize_mint2", parsed: { type: "other" } };
        default:
            // Token-2022 extension instructions (transfer hooks, permanent delegate, fees, ...) land here.
            return { name: `extension_${d[0]}`, parsed: { type: "opaque" } };
    }
}
function decodeAta(ix) {
    const kind = ix.data.length === 0 ? 0 : ix.data[0];
    if (kind === 0 || kind === 1) {
        need(ix, 0, 6);
        return {
            name: kind === 0 ? "create" : "create_idempotent",
            parsed: {
                type: "ata_create",
                payer: acc(ix, 0),
                ata: acc(ix, 1),
                owner: acc(ix, 2),
                mint: acc(ix, 3),
                tokenProgram: acc(ix, 5),
                idempotent: kind === 1,
            },
        };
    }
    if (kind === 2)
        return { name: "recover_nested", parsed: { type: "opaque" } };
    return { name: `unknown_${kind}`, parsed: { type: "opaque" } };
}
function decodeComputeBudget(ix) {
    need(ix, 1, 0);
    const d = ix.data;
    switch (d[0]) {
        case 1:
            return { name: "request_heap_frame", parsed: { type: "other" } };
        case 2:
            need(ix, 5, 0);
            return { name: "set_compute_unit_limit", parsed: { type: "compute_limit", units: readU32(d, 1) } };
        case 3:
            need(ix, 9, 0);
            return { name: "set_compute_unit_price", parsed: { type: "compute_price", microLamports: readU64(d, 1) } };
        case 4:
            return { name: "set_loaded_accounts_data_size_limit", parsed: { type: "other" } };
        default:
            return { name: `unknown_${d[0]}`, parsed: { type: "opaque" } };
    }
}
// ---------------------------------------------------------------------------------------------
// Jupiter v6 (Anchor). Instruction *names* come from sha256("global:<name>"); route arguments are
// decoded from the tail of the data (…in_amount u64, quoted_out u64, slippage_bps u16, fee_bps u8).
// ---------------------------------------------------------------------------------------------
export const JUPITER_INSTRUCTIONS = [
    "route",
    "route_with_token_ledger",
    "shared_accounts_route",
    "shared_accounts_route_with_token_ledger",
    "exact_out_route",
    "shared_accounts_exact_out_route",
    "set_token_ledger",
    "create_open_orders",
    "create_token_account",
    "claim",
    "claim_token",
];
const JUPITER_BY_DISC = new Map(JUPITER_INSTRUCTIONS.map((n) => [anchorDiscriminator(n), n]));
const JUPITER_ROUTES = new Set(["route", "shared_accounts_route", "exact_out_route", "shared_accounts_exact_out_route"]);
function decodeJupiter(ix) {
    need(ix, 8, 0);
    const d = ix.data;
    const disc = toHex(d.subarray(0, 8));
    const name = JUPITER_BY_DISC.get(disc);
    if (!name)
        return { name: `disc:${disc}`, discriminator: disc, parsed: { type: "opaque" } };
    if (!JUPITER_ROUTES.has(name))
        return { name, discriminator: disc, parsed: { type: "other" } };
    need(ix, 8 + 19, 0);
    const n = d.length;
    const shared = name.startsWith("shared_accounts");
    const a = ix.accounts;
    const at = (i) => a[i]?.pubkey;
    let authority;
    let userSource;
    let destination;
    let sourceMint;
    let destinationMint;
    if (shared) {
        // tokenProgram, programAuthority, userTransferAuthority, sourceTokenAccount, programSource,
        // programDestination, destinationTokenAccount, sourceMint, destinationMint, ...
        authority = at(2);
        userSource = at(3);
        destination = at(6);
        sourceMint = at(7);
        destinationMint = at(8);
    }
    else {
        // tokenProgram, userTransferAuthority, userSourceTokenAccount, userDestinationTokenAccount,
        // destinationTokenAccount(optional -> program id when absent), destinationMint, ...
        authority = at(1);
        userSource = at(2);
        const optional = at(4);
        destination = optional && optional !== JUPITER_V6_PROGRAM ? optional : at(3);
        destinationMint = at(5);
    }
    return {
        name,
        discriminator: disc,
        parsed: {
            type: "swap_route",
            protocol: "jupiter",
            mode: name.includes("exact_out") ? "exact_out" : "exact_in",
            amount: readU64(d, n - 19),
            otherAmount: readU64(d, n - 11),
            slippageBps: readU16(d, n - 3),
            platformFeeBps: d[n - 1],
            authority,
            userSource,
            destination,
            sourceMint,
            destinationMint,
        },
    };
}
function decodeAnchorOpaque(ix) {
    if (ix.data.length >= 8) {
        const disc = toHex(ix.data.subarray(0, 8));
        return { name: `disc:${disc}`, discriminator: disc, parsed: { type: "opaque" } };
    }
    return { name: "unknown", parsed: { type: "opaque" } };
}
export function decodeInstruction(ix, index) {
    const programLabel = PROGRAM_LABELS[ix.programId] ?? shortAddr(ix.programId);
    let r;
    try {
        switch (ix.programId) {
            case SYSTEM_PROGRAM:
                r = decodeSystem(ix);
                break;
            case TOKEN_PROGRAM:
            case TOKEN_2022_PROGRAM:
                r = decodeToken(ix);
                break;
            case ATA_PROGRAM:
                r = decodeAta(ix);
                break;
            case COMPUTE_BUDGET_PROGRAM:
                r = decodeComputeBudget(ix);
                break;
            case MEMO_PROGRAM:
            case MEMO_V1_PROGRAM:
                r = { name: "memo", parsed: { type: "memo", text: new TextDecoder().decode(ix.data) } };
                break;
            case JUPITER_V6_PROGRAM:
                r = decodeJupiter(ix);
                break;
            default:
                r = decodeAnchorOpaque(ix);
        }
    }
    catch (e) {
        if (!(e instanceof Malformed))
            throw e;
        r = { name: "malformed", parsed: { type: "malformed", reason: e.message } };
    }
    return { index, programId: ix.programId, programLabel, ...r, accounts: ix.accounts, data: ix.data };
}
export function decodeAll(instructions) {
    return instructions.map((ix, i) => decodeInstruction(ix, i));
}
/** One-line description used in reports. */
export function describeInstruction(d) {
    const p = d.parsed;
    const sol = (l) => `${formatUnits(l, 9)} SOL`;
    switch (p.type) {
        case "sol_transfer":
            return `Transfer ${sol(p.lamports)} ${shortAddr(p.from)} → ${shortAddr(p.to)}`;
        case "sol_create_account":
            return `Create account ${shortAddr(p.newAccount)} funded with ${sol(p.lamports)}, owner ${shortAddr(p.owner)}`;
        case "assign":
            return `Assign ${shortAddr(p.account)} to program ${shortAddr(p.owner)}`;
        case "token_transfer":
            return `Token transfer ${p.amount} raw units${p.mint ? ` of ${shortAddr(p.mint)}` : ""} → ${shortAddr(p.destination)}`;
        case "token_approve":
            return `APPROVE delegate ${shortAddr(p.delegate)} for ${p.amount} raw units`;
        case "token_revoke":
            return `Revoke delegate on ${shortAddr(p.source)}`;
        case "authority_change":
            return `SET AUTHORITY (${p.kind}) on ${shortAddr(p.target)} → ${p.newAuthority ? shortAddr(p.newAuthority) : "none"}`;
        case "token_close":
            return `Close token account ${shortAddr(p.account)}, remainder → ${shortAddr(p.destination)}`;
        case "token_burn":
            return `Burn ${p.amount} raw units`;
        case "token_mint":
            return `Mint ${p.amount} raw units to ${shortAddr(p.destination)}`;
        case "token_sync_native":
            return `Sync wrapped SOL account ${shortAddr(p.account)}`;
        case "ata_create":
            return `Create token account for owner ${shortAddr(p.owner)} (mint ${shortAddr(p.mint)})`;
        case "compute_limit":
            return `Compute unit limit ${p.units}`;
        case "compute_price":
            return `Compute unit price ${p.microLamports} µ-lamports`;
        case "memo":
            return `Memo "${p.text.slice(0, 60)}"`;
        case "swap_route":
            return `Swap (${p.protocol}, ${p.mode.replace("_", "-")}) amount ${p.amount}, slippage ${p.slippageBps} bps`;
        case "malformed":
            return `Malformed ${d.programLabel} instruction: ${p.reason}`;
        default:
            return `${d.programLabel}: ${d.name}`;
    }
}
//# sourceMappingURL=decode.js.map