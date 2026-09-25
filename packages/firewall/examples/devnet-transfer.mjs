// End-to-end on devnet (free): intent -> build -> inspect + simulate -> sign -> send.
//   solana-keygen new --outfile ~/.config/solana/id.json && solana airdrop 1 --url devnet
//   TO=<recipient address> node examples/devnet-transfer.mjs
import { AgentTxFirewall, KeypairSigner, renderReport } from "../dist/index.js";

const signer = KeypairSigner.fromFile(process.env.KEYPAIR ?? `${process.env.HOME}/.config/solana/id.json`);
const to = process.env.TO;
if (!to) throw new Error("Set TO=<recipient address>");

const fw = new AgentTxFirewall({
  policy: {
    cluster: "devnet",
    signer: signer.publicKey,
    destinations: { allow: [{ address: to }] },
    limits: { maxSolPerTx: "0.05" },
  },
  rpc: "devnet",
  signer,
  auditLog: ".agenttx/audit.jsonl",
});

const result = await fw.execute({ action: "transfer", asset: "SOL", to, amount: "0.01" });
console.log(renderReport(result.report, { color: true, verbose: true }));
console.log(result.signature ? `\nSent: https://explorer.solana.com/tx/${result.signature}?cluster=devnet` : "\nNot sent.");
