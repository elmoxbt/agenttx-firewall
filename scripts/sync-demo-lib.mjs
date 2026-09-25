#!/usr/bin/env node
// Rebuilds packages/firewall and refreshes apps/demo's checked-in copy of it.
// The demo intentionally does NOT resolve the firewall via a workspace/bare-specifier
// import: apps/demo/lib/agenttx-firewall is a plain, self-contained compiled-JS folder
// so the Vercel deployment has no monorepo-specific resolution to get right. Run this
// (via `npm run sync-demo` from the repo root) after any change under packages/firewall/src.
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const firewallDir = join(root, "packages/firewall");
const demoLibDir = join(root, "apps/demo/lib/agenttx-firewall");

console.log("> building packages/firewall");
execFileSync("npm", ["run", "build"], { cwd: firewallDir, stdio: "inherit" });

const distDir = join(firewallDir, "dist");
if (!existsSync(distDir)) throw new Error(`Expected ${distDir} to exist after build`);

console.log(`> refreshing ${demoLibDir}`);
rmSync(demoLibDir, { recursive: true, force: true });
mkdirSync(demoLibDir, { recursive: true });
cpSync(distDir, demoLibDir, { recursive: true });

// The demo's API route only ever imports index.js; drop files it has no use for.
const cliPath = join(demoLibDir, "cli.js");
if (existsSync(cliPath)) rmSync(cliPath);
prune(demoLibDir, [".d.ts", ".map"]);

function prune(dir, extensions) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) prune(p, extensions);
    else if (extensions.some((ext) => entry.endsWith(ext))) rmSync(p);
  }
}

console.log("> done. Review `git status` in apps/demo/lib before committing.");
