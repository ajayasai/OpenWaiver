"use strict";
const $ = selector => document.querySelector(selector);
let token = "", epoch = 0, evaluation = null, pending = null;
function invalidate(message) {
  epoch += 1;
  if (pending) pending.abort();
  pending = null;
  evaluation = null;
  $("#decision").hidden = true;
  $("#result-json").textContent = "";
  $("#blockers").replaceChildren();
  $("#check-results").replaceChildren();
  $("#binding").textContent = "";
  $("#totals").textContent = "";
  $("#verdict").textContent = "";
  $("#download").disabled = true;
  $("#evaluate").disabled = !token;
  if (message) $("#status").textContent = message;
}
async function request(url, options = {}) {
  const response = await fetch(url, {...options, headers: {Authorization: `Bearer ${token}`, "Content-Type": "application/json"}});
  const data = await response.json();
  if (!response.ok) throw Error(typeof data.detail === "string" ? data.detail : `Request rejected (${response.status})`);
  return data;
}
function disconnect() {
  token = "";
  invalidate("Disconnected. Displayed release data and credentials cleared.");
  $("#token").value = "";
  $("#contract").value = "";
  $("#receipts").value = "[]";
  $("#contract-file").value = "";
  $("#receipt-files").value = "";
  $("#identity").textContent = "Disconnected. Credentials and evidence stay in memory only.";
}
$("#disconnect").onclick = disconnect;
$("#login").onsubmit = async event => {
  event.preventDefault();
  token = $("#token").value;
  $("#token").value = "";
  invalidate("Connecting…");
  const generation = epoch;
  try {
    const actor = await request("/api/me");
    if (generation !== epoch) return;
    $("#identity").textContent = `${actor.name} · ${actor.role} · project-authorized evaluation`;
    $("#status").textContent = "Connected. Load the contract and signed producer receipts.";
  } catch (error) {
    if (generation !== epoch) return;
    disconnect();
    $("#status").textContent = error.message;
  }
};
for (const id of ["#contract", "#receipts"]) $(id).addEventListener("input", () => invalidate("Inputs changed. Evaluate again before using a decision."));
$("#contract-file").onchange = async event => {
  invalidate("Loading contract…");
  const generation = epoch, file = event.target.files[0];
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) { $("#status").textContent = "Contract exceeds 4 MiB."; return; }
  const text = await file.text();
  if (generation === epoch) { $("#contract").value = text; $("#status").textContent = "Contract loaded. No decision yet."; }
};
$("#receipt-files").onchange = async event => {
  invalidate("Loading receipts…");
  const generation = epoch, files = [...event.target.files];
  if (files.length > 1000 || files.reduce((s,f) => s + f.size,0) > 16 * 1024 * 1024) { $("#status").textContent = "Receipt input budget exceeded."; return; }
  try {
    const receipts = await Promise.all(files.map(async file => JSON.parse(await file.text())));
    if (generation === epoch) { $("#receipts").value = JSON.stringify(receipts, null, 2); $("#status").textContent = "Receipts loaded. No decision yet."; }
  } catch (_) { if (generation === epoch) $("#status").textContent = "Invalid receipt JSON."; }
};
function textNode(tag, text) { const node = document.createElement(tag); node.textContent = text; return node; }
function render(result) {
  evaluation = result;
  $("#decision").hidden = false;
  $("#decision").dataset.pass = String(result.gate_pass);
  $("#verdict").textContent = result.gate_pass ? "Contract satisfied" : "Release blocked";
  $("#totals").textContent = `${result.checks.length} required checks · ${result.risk.waived_findings} waived findings`;
  $("#binding").textContent = `${result.project} / ${result.revision}\nContract SHA-256: ${result.contract_sha256}\nAssessed: ${result.assessed_at}`;
  for (const check of result.checks) {
    const row = textNode("div", ""); row.className = "check";
    row.append(textNode("strong", `${check.gate_pass ? "PASS" : "BLOCKED"} · ${check.tool} / ${check.stream}`));
    row.append(textNode("p", `Pinned run: ${check.run_id}`));
    row.append(textNode("p", check.producer ? `Authorized execution completed ${check.producer.finished_at}` : "No valid authorized execution receipt."));
    $("#check-results").append(row);
  }
  for (const blocker of result.blockers) {
    const row = textNode("div", ""); row.className = "blocker";
    row.append(textNode("code", blocker.code), textNode("p", blocker.message));
    if (blocker.actual !== undefined) row.append(textNode("p", `Actual ${blocker.actual}; maximum ${blocker.maximum}`));
    $("#blockers").append(row);
  }
  if (!result.blockers.length) $("#blockers").append(textNode("p", "No blockers under this exact contract and current trust policy."));
  $("#result-json").textContent = JSON.stringify(result, null, 2);
  $("#download").disabled = false;
  $("#status").textContent = "Evaluation complete. No waiver or approval was changed.";
}
$("#evaluate").onclick = async () => {
  invalidate("Evaluating current evidence…");
  const generation = epoch;
  pending = new AbortController();
  $("#evaluate").disabled = true;
  try {
    const body = {contract: JSON.parse($("#contract").value), receipts: JSON.parse($("#receipts").value)};
    const result = await request("/api/release-assurance/evaluate", {method: "POST", body: JSON.stringify(body), signal: pending.signal});
    if (generation === epoch) render(result);
  } catch (error) {
    if (generation === epoch) $("#status").textContent = error.message;
  } finally { if (generation === epoch) { pending = null; $("#evaluate").disabled = !token; } }
};
$("#download").onclick = () => {
  if (!evaluation) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(evaluation, null, 2)], {type: "application/json"}));
  const link = document.createElement("a"); link.href = url; link.download = "release-evaluation.json";
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
