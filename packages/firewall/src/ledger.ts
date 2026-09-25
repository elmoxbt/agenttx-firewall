import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/** Rolling-window record of SOL the agent has spent, optionally persisted to a JSON file. */
export class SpendingLedger {
  private entries: { ts: number; lamports: string }[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        this.entries = JSON.parse(readFileSync(file, "utf8")) as { ts: number; lamports: string }[];
      } catch {
        this.entries = [];
      }
    }
  }

  record(lamports: bigint, ts: number = Date.now()): void {
    this.entries.push({ ts, lamports: lamports.toString() });
    if (this.file) {
      mkdirSync(dirname(this.file), { recursive: true });
      writeFileSync(this.file, JSON.stringify(this.entries));
    }
  }

  spentSince(windowMs: number, now: number = Date.now()): bigint {
    return this.entries.filter((e) => e.ts >= now - windowMs).reduce((n, e) => n + BigInt(e.lamports), 0n);
  }
}
