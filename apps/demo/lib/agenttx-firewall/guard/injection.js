import { decodeBase58, isAddress } from "../util/base58.js";
const RULES = [
    {
        id: "unlimited-approval",
        severity: "high",
        description: "Asks for an unlimited / maximum token approval or allowance",
        pattern: /\b(?:unlimited|infinite|maximum|max(?:imum)?)\s+(?:token\s+)?(?:spending|approval|allowance|delegat\w*)|\b(?:approve|allowance|delegate)\b[^.\n]{0,80}\b(?:unlimited|infinite|all\s+(?:of\s+)?(?:your\s+)?tokens|u64::?max|18446744073709551615)/i,
    },
    {
        id: "approval-request",
        severity: "medium",
        description: "Instructs the agent to approve / delegate spending to an address",
        pattern: /\b(?:approve|delegate)\b[^.\n]{0,60}\b(?:spend\w*|spender|address|wallet|contract|program)\b/i,
    },
    {
        id: "authority-change",
        severity: "high",
        description: "Asks to change account authority or ownership",
        pattern: /\b(?:set[\s_-]?authority|change\s+(?:the\s+)?(?:owner|authority)|transfer\s+(?:the\s+)?(?:ownership|authority)|assign\s+(?:the\s+)?(?:account|owner)|delegate\s+(?:authority|control))\b/i,
    },
    {
        id: "secret-exfiltration",
        severity: "high",
        description: "Mentions private keys, seed phrases or keypair files",
        pattern: /\b(?:private\s+key|secret\s+key|seed\s+phrase|recovery\s+phrase|mnemonic|keypair\s+file|id\.json)\b/i,
    },
    {
        id: "instruction-override",
        severity: "high",
        description: "Tries to override earlier instructions, policies or safety rules",
        pattern: /\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|system|safety|security|the)\b[^.\n]{0,30}\b(?:instructions?|rules?|prompts?|polic(?:y|ies)|guardrails?|limits?|checks?)\b/i,
    },
    {
        id: "concealment",
        severity: "high",
        description: "Asks the agent to hide actions from the user",
        pattern: /\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|reveal|show|notify)\b[^.\n]{0,30}\b(?:user|human|owner|operator)\b/i,
    },
    {
        id: "drain-funds",
        severity: "high",
        description: "Asks to send all or most funds somewhere",
        pattern: /\b(?:send|transfer|deposit|move|sweep)\b[^.\n]{0,60}\b(?:all|entire|remaining|full|whole)\b[^.\n]{0,40}\b(?:funds|balance|sol|tokens?|usdc|assets)\b/i,
    },
    {
        id: "prerequisite-action",
        severity: "medium",
        description: "Tool output demands an extra 'required' step before the task can finish",
        pattern: /\b(?:to\s+complete|before\s+(?:you\s+)?(?:can\s+)?(?:proceed|continue|swap|complete)|in\s+order\s+to|you\s+must|required\s+step|first,?)\b[^.\n]{0,80}\b(?:approve|send|transfer|sign|delegate|whitelist|deposit)\b/i,
    },
    {
        id: "role-hijack",
        severity: "medium",
        description: "Attempts to redefine the agent's role or claim system authority",
        pattern: /\b(?:you\s+are\s+now|new\s+instructions?|system\s+prompt|as\s+the\s+(?:system\s+)?administrator|developer\s+mode|act\s+as\s+(?:an?\s+)?(?:admin|root))\b/i,
    },
    {
        id: "ascii-smuggling",
        severity: "high",
        description: "Contains invisible Unicode tag characters (hidden instructions)",
        pattern: /[\u{E0000}-\u{E007F}]/u,
    },
    {
        id: "hidden-unicode",
        severity: "medium",
        description: "Contains zero-width or bidirectional control characters",
        pattern: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/,
    },
    {
        id: "html-comment",
        severity: "medium",
        description: "Contains an HTML comment (a common place to hide instructions)",
        pattern: /<!--[\s\S]*?-->/,
    },
    {
        id: "opaque-blob",
        severity: "medium",
        description: "Contains a long base64 blob (possibly a pre-built transaction)",
        pattern: /[A-Za-z0-9+/]{300,}={0,2}/,
    },
    {
        id: "urgency",
        severity: "low",
        description: "Uses urgency language",
        pattern: /\b(?:urgent(?:ly)?|immediately|right\s+now|asap|last\s+chance)\b/i,
    },
];
const ORDER = { low: 1, medium: 2, high: 3 };
function excerpt(text, index, length) {
    const start = Math.max(0, index - 30);
    const end = Math.min(text.length, index + length + 50);
    return text.slice(start, end).replace(/\s+/g, " ").trim().slice(0, 160);
}
export function extractAddresses(text) {
    const found = new Set();
    for (const m of text.matchAll(/[1-9A-HJ-NP-Za-km-z]{32,44}/g)) {
        if (isAddress(m[0]) && decodeBase58(m[0]).length === 32)
            found.add(m[0]);
    }
    return [...found];
}
/** Scan untrusted text (tool output, web content, emails) for prompt-injection patterns aimed at wallets. */
export function scanText(text) {
    const findings = [];
    for (const rule of RULES) {
        const m = rule.pattern.exec(text);
        if (m) {
            findings.push({
                rule: rule.id,
                severity: rule.severity,
                description: rule.description,
                excerpt: rule.id === "opaque-blob" ? `${m[0].slice(0, 40)}… (${m[0].length} chars)` : excerpt(text, m.index, m[0].length),
            });
        }
    }
    let highest = "none";
    for (const f of findings)
        if (highest === "none" || ORDER[f.severity] > ORDER[highest])
            highest = f.severity;
    return { findings, addresses: extractAddresses(text), highest };
}
//# sourceMappingURL=injection.js.map