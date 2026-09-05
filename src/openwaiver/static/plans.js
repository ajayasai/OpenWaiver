/* Reviewed YAML changes never contain trusted approvals. */
"use strict";
async function renderPlans() {
  const area = $("#plans-view");
  if (preview || !state.run) {
    area.innerHTML = '<div class="panel panel-content"><h2>Review plans</h2><p>Start the authenticated application and import a run to prepare Git-reviewable changes.</p></div>';
    return;
  }
  const editable = state.actor.role !== "viewer";
  area.innerHTML = `<div class="panel"><div class="panel-head"><div><h2>Propose together. Approve independently.</h2><p>Select exact findings, review the YAML, preview its effects, then apply atomically.</p></div></div>
    <div class="panel-content"><p>Every change is pinned to the current audit head. Edits to approved waivers clear approvals. A Git merge is not an engineering approval.</p>
      <form id="plan-template-form" class="plan-grid">
        <label>Occurrence IDs (comma-separated)<input id="plan-ids" required placeholder="finding-9, finding-10" ${editable ? "" : "disabled"}></label>
        <label>Independent reviewers (comma-separated)<input id="plan-reviewers" required placeholder="reviewer, signoff" ${editable ? "" : "disabled"}></label>
        <label>Engineering rationale<textarea id="plan-rationale" required minlength="12" ${editable ? "" : "disabled"}></textarea></label>
        <p class="note">Generated proposals are bounded to the selected run's exact revision. Edit the YAML for a date-bound proposal.</p>
        <button class="button" id="generate-plan" ${editable ? "" : "disabled"}>Generate proposal YAML</button>
      </form>
      <label for="plan-yaml">Git-reviewable YAML (proposal or amendment plan)</label>
      <textarea id="plan-yaml" class="policy-textarea" spellcheck="false" ${editable ? "" : "readonly"}></textarea>
      <div class="context-actions"><button id="preview-plan" class="button" ${editable ? "" : "disabled"}>Preview changes</button><button id="apply-plan" class="button primary" disabled>Apply reviewed plan</button></div>
      <h3>Preview / transaction result</h3><pre id="plan-result" class="plan-result" aria-live="polite">No plan has been previewed. No changes have been made.</pre>
    </div></div>`;
  let reviewedDigest = null;
  function invalidate() {
    reviewedDigest = null;
    $("#apply-plan").disabled = true;
  }
  $("#plan-yaml").oninput = invalidate;
  $("#plan-template-form").onsubmit = event => {
    event.preventDefault();
    invalidate();
    guard(async () => {
      const result = await post("/api/review-plans/template", {
        run_id: state.run.id,
        violation_ids: $("#plan-ids").value.split(",").map(x => x.trim()),
        rationale: $("#plan-rationale").value,
        reviewers: $("#plan-reviewers").value.split(",").map(x => x.trim()),
        valid_revision: state.run.revision
      });
      $("#plan-yaml").value = result.yaml;
      $("#plan-result").textContent = "Template generated. Review the YAML, then preview. Nothing has been applied.";
    });
  };
  $("#preview-plan").onclick = () => {
    invalidate();
    guard(async () => {
      const text = $("#plan-yaml").value;
      const result = await post("/api/review-plans/preview", {yaml: text});
      if (text !== $("#plan-yaml").value) return; // Ignore a stale asynchronous preview.
      reviewedDigest = result.preview_digest;
      $("#plan-result").textContent = JSON.stringify(result, null, 2);
      $("#apply-plan").disabled = false;
    });
  };
  $("#apply-plan").onclick = () => {
    if (!reviewedDigest) return;
    const body = {yaml: $("#plan-yaml").value, expected_digest: reviewedDigest};
    invalidate();
    guard(async () => {
      const result = await post("/api/review-plans/apply", body);
      $("#plan-result").textContent = JSON.stringify(result, null, 2);
      state.waivers = (await api("/api/waivers?limit=1000")).items;
      await loadRun();
      toast("Plan applied atomically. Independent approvals are still required.");
    });
  };
}
