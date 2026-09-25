import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
/** Rolling-window record of SOL the agent has spent, optionally persisted to a JSON file. */
export class SpendingLedger {
    file;
    entries = [];
    constructor(file) {
        this.file = file;
        if (file && existsSync(file)) {
            try {
                this.entries = JSON.parse(readFileSync(file, "utf8"));
            }
            catch {
                this.entries = [];
            }
        }
    }
    record(lamports, ts = Date.now()) {
        this.entries.push({ ts, lamports: lamports.toString() });
        if (this.file) {
            mkdirSync(dirname(this.file), { recursive: true });
            writeFileSync(this.file, JSON.stringify(this.entries));
        }
    }
    spentSince(windowMs, now = Date.now()) {
        return this.entries.filter((e) => e.ts >= now - windowMs).reduce((n, e) => n + BigInt(e.lamports), 0n);
    }
}
//# sourceMappingURL=ledger.js.map