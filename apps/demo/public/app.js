import {
  SAMPLE_TX,
  SAMPLE_INTENT_SWAP,
  SAMPLE_INTENT_MALICIOUS,
  SAMPLE_TOOL_OUTPUT,
  SAMPLE_POLICY,
} from "./samples.js";

const $ = (sel) => document.querySelector(sel);
const txInput = $("#txInput");
const intentInput = $("#intentInput");
const contextInput = $("#contextInput");
const policyInput = $("#policyInput");
const simulateToggle = $("#simulateToggle");
const runBtn = $("#runBtn");
const reportEmpty = $("#reportEmpty");
const reportOut = $("#reportOut");

policyInput.value = JSON.stringify(SAMPLE_POLICY, null, 2);

let activeTab = "tx";
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    activeTab = tab.dataset.tab;
    for (const t of document.querySelectorAll(".tab")) {
      t.classList.toggle("is-active", t === tab);
      t.setAttribute("aria-selected", String(t === tab));
    }
    for (const panel of document.querySelectorAll(".field-tab")) {
      panel.hidden = panel.dataset.panel !== activeTab;
    }
  });
}

const SAMPLES = [
  { label: "Clean transfer", kind: "allow", tab: "tx", tx: SAMPLE_TX.transferOk },
  { label: "Unknown destination", kind: "block", tab: "tx", tx: SAMPLE_TX.transferUnknownDest },
  { label: "Jupiter swap (valid)", kind: "allow", tab: "tx", tx: SAMPLE_TX.jupiterSwap },
  { label: "Swap output redirected", kind: "block", tab: "tx", tx: SAMPLE_TX.jupiterSwapRedirected },
  { label: "Slippage too high", kind: "block", tab: "tx", tx: SAMPLE_TX.jupiterSwapHighSlippage },
  { label: "Priority fee too high", kind: "block", tab: "tx", tx: SAMPLE_TX.expensivePriorityFee },
  {
    label: "Malicious approval + injection",
    kind: "block",
    tab: "tx",
    tx: SAMPLE_TX.maliciousApprove,
    context: SAMPLE_TOOL_OUTPUT,
  },
  {
    label: "Intent: swap",
    kind: "allow",
    tab: "intent",
    intent: JSON.stringify(SAMPLE_INTENT_SWAP, null, 2),
  },
  {
    label: "Intent: hijacked approval",
    kind: "block",
    tab: "intent",
    intent: JSON.stringify(SAMPLE_INTENT_MALICIOUS, null, 2),
    context: SAMPLE_TOOL_OUTPUT,
  },
];

const samplesEl = $("#samples");
for (const s of SAMPLES) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "sample-btn";
  btn.dataset.kind = s.kind;
  btn.textContent = s.label;
  btn.addEventListener("click", () => {
    document.querySelector(`.tab[data-tab="${s.tab}"]`).click();
    if (s.tx) txInput.value = s.tx;
    if (s.intent) intentInput.value = s.intent;
    contextInput.value = s.context ?? "";
  });
  samplesEl.appendChild(btn);
}
document.querySelector(`.sample-btn`)?.click();

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderReport(report) {
  reportEmpty.hidden = true;
  reportOut.hidden = false;

  const s = report.summary;
  const summaryLines = [
    `<div><b>Program</b> ${escapeHtml(s.programs.join(", "))}</div>`,
    `<div><b>Action</b> ${escapeHtml(s.action)}</div>`,
    s.input ? `<div><b>Input</b> ${escapeHtml(s.input)}</div>` : "",
    s.expectedOutput ? `<div><b>Expected output</b> ${escapeHtml(s.expectedOutput)}</div>` : "",
    s.recipient ? `<div><b>Recipient</b> ${escapeHtml(s.recipient)}</div>` : "",
  ].filter(Boolean).join("");

  const checks = report.checks
    .map((c) => {
      const details = (c.details ?? []).filter((d) => d.replace(/^#\d+ /, "") !== c.message);
      return `<div class="check" data-s="${c.status}" data-critical="${c.critical ? 1 : 0}">
        <div class="check__tag">${c.status}</div>
        <div>
          <div class="check__name">${escapeHtml(c.name)}</div>
          ${c.status !== "pass" ? `<div class="check__msg">${escapeHtml(c.message)}</div>` : ""}
          ${details.length ? `<ul class="check__details">${details.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>` : ""}
        </div>
      </div>`;
    })
    .join("");

  reportOut.innerHTML = `
    <div class="verdict" data-v="${report.verdict}">
      <span class="verdict__label">${report.verdict === "BLOCK" ? "BLOCKED" : report.verdict}</span>
      <span class="verdict__risk">RISK <b>${report.risk}</b></span>
    </div>
    <div class="summary">${summaryLines}</div>
    <div class="checklist">${checks}</div>
    <details class="raw">
      <summary>Raw JSON report</summary>
      <pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre>
    </details>
  `;
}

function renderError(message) {
  reportEmpty.hidden = true;
  reportOut.hidden = false;
  reportOut.innerHTML = `<div class="error-box">${escapeHtml(message)}</div>`;
}

async function run() {
  runBtn.disabled = true;
  runBtn.textContent = "Inspecting…";
  try {
    let policy;
    try {
      policy = policyInput.value.trim() ? JSON.parse(policyInput.value) : {};
    } catch {
      throw new Error("Policy is not valid JSON.");
    }

    const untrusted = contextInput.value.trim() ? [contextInput.value] : [];
    const payload = { policy, context: { untrusted }, simulate: simulateToggle.checked };

    if (activeTab === "intent") {
      if (!intentInput.value.trim()) throw new Error("Paste an intent, or pick a sample above.");
      let intent;
      try {
        intent = JSON.parse(intentInput.value);
      } catch {
        throw new Error("Intent is not valid JSON.");
      }
      payload.mode = "intent";
      payload.intent = intent;
    } else {
      if (!txInput.value.trim()) throw new Error("Paste a transaction, or pick a sample above.");
      payload.mode = "transaction";
      payload.transaction = txInput.value.trim();
    }

    const res = await fetch("/api/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new Error(data?.error ?? `Request failed (${res.status})`);
    if (data.error) throw new Error(data.error);
    renderReport(data.report);
  } catch (e) {
    renderError(e.message ?? String(e));
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = activeTab === "intent" ? "Evaluate intent" : "Inspect transaction";
  }
}

runBtn.addEventListener("click", run);
for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    runBtn.textContent = tab.dataset.tab === "intent" ? "Evaluate intent" : "Inspect transaction";
  });
}
