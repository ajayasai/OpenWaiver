"""Pure, fail-closed assessment. Approximate matches are suggestions, never suppressions."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date

from .identity import approval_digest, bucket, fingerprint, similarity
from .models import Policy, Run, Waiver


def provenance(run: Run) -> dict[str, str]:
    return {k: getattr(run, k) for k in ("tool_version", "rule_deck_digest", "configuration_digest")}


def approval_problems(w: Waiver, policy: Policy, today: date) -> list[str]:
    errors = []
    if w.expires_on and today > w.expires_on:
        errors.append("expired")
    if w.expires_on and (w.expires_on - w.created_at.date()).days > policy.max_waiver_days:
        errors.append("expiration exceeds policy horizon")
    if policy.require_evidence and not w.evidence:
        errors.append("evidence required")
    if w.target.rule in policy.forbidden_rules:
        errors.append("rule is non-waivable")
    if w.target.multiplicity != 1:
        errors.append("aggregate markers require instance-level disambiguation")
    return errors


def effective_problems(w: Waiver, run: Run, current, policy: Policy, today: date) -> list[str]:
    reasons = approval_problems(w, policy, today)
    if w.status != "approved":
        reasons.append(w.status)
    if w.valid_revision and w.valid_revision != run.revision:
        reasons.append("revision bound no longer valid")
    if w.baseline_provenance != provenance(run):
        reasons.append("tool, rule-deck or configuration changed")
    if w.target.context_hash != current.context_hash:
        reasons.append("surrounding design context changed or disappeared")
    if (policy.require_context_across_revisions and run.revision != w.baseline_revision
            and not (w.target.context_hash and current.context_hash)):
        reasons.append("context unknown across revisions")
    good = {a.actor for a in w.approvals if a.decision == "approve"
            and a.content_digest == approval_digest(w) and a.actor in w.reviewers
            and a.actor not in (w.owner, w.creator)}
    if len(good) < policy.quorum(w):
        reasons.append("approval quorum missing or content changed")
    return list(dict.fromkeys(reasons))


def assess(run: Run, waivers: list[Waiver], policy: Policy, today: date) -> dict:
    scoped = [w for w in waivers if w.scope == run.scope]
    exact = defaultdict(list)
    candidates = defaultdict(list)
    object_candidates = defaultdict(list)
    occurrences = defaultdict(list)
    for v in run.violations:
        occurrences[fingerprint(v)].append(v)
    for w in scoped:
        if w.status != "revoked":
            exact[w.fingerprint].append(w)
            candidates[bucket(w.target)].append(w)
            if w.target.object_id:
                object_candidates[(w.target.category, w.target.rule, w.target.object_id)].append(w)
    rows, matched, candidate_seen = [], set(), set()
    truncated = set()
    for v in run.violations:
        fp = fingerprint(v)
        hits = exact.get(fp, [])
        row = {"violation_id": v.id, "fingerprint": fp, "status": "open",
               "waiver_ids": [], "reasons": [], "candidates": [], "violation": v.model_dump(mode="json")}
        if hits:
            row["waiver_ids"] = [w.id for w in hits]
            matched.update(w.id for w in hits)
            if len(hits) != 1 or len(occurrences[fp]) != 1:
                row.update(status="ambiguous", reasons=["non-unique exact identity; no suppression"])
            else:
                w = hits[0]
                problems = effective_problems(w, run, v, policy, today)
                if not problems:
                    row["status"] = "waived"
                elif "expired" in problems:
                    row["status"] = "expired"
                elif w.status != "approved":
                    row["status"] = "pending" if w.status in ("proposed", "submitted") else w.status
                else:
                    row["status"] = "stale"
                row["reasons"] = problems
        else:
            pool = list(candidates.get(bucket(v), []))
            if v.object_id:
                pool += object_candidates.get((v.category, v.rule, v.object_id), [])
            pool = list({w.id: w for w in pool}.values())
            if len(pool) > policy.candidate_limit:
                truncated.update(w.id for w in pool)
                row.update(status="ambiguous", reasons=["candidate budget exceeded; narrow check stream"])
            else:
                for w in pool:
                    score, why = similarity(w.target, v, policy)
                    if score >= .7:
                        candidate_seen.add(w.id)
                        row["candidates"].append({"waiver_id": w.id, "score": round(score, 4), "reasons": why})
                row["candidates"].sort(key=lambda c: (-c["score"], c["waiver_id"]))
                if row["candidates"]:
                    row["status"] = "needs_review" if len(row["candidates"]) == 1 else "ambiguous"
                    row["reasons"] = ["changed violation: explicit rebind and fresh approval required"]
        rows.append(row)
    # Multiple current targets suggested for a waiver are ambiguous in both directions.
    uses = Counter(c["waiver_id"] for r in rows for c in r["candidates"])
    for row in rows:
        if any(uses[c["waiver_id"]] > 1 or c["waiver_id"] in matched for c in row["candidates"]):
            row.update(status="ambiguous", reasons=["candidate correspondence is not one-to-one"])
    matched_states = defaultdict(set)
    for row in rows:
        for waiver_id in row["waiver_ids"]:
            matched_states[waiver_id].add(row["status"])
    outcomes = []
    for w in scoped:
        if w.status == "revoked":
            state = "revoked"
        elif w.id in matched:
            states = matched_states[w.id]
            state = "active" if states == {"waived"} else sorted(states)[0]
        elif w.id in candidate_seen:
            state = "needs_review"
        elif w.id in truncated:
            state = "not_observed"
        elif run.complete and w.target.category in run.checked_categories:
            state = "unused"
        else:
            state = "not_observed"
        outcomes.append({"waiver_id": w.id, "status": state, "owner": w.owner,
                         "expires_on": w.expires_on.isoformat() if w.expires_on else None})
    blockers = []
    if not run.complete:
        blockers.append({"code": "incomplete_run", "message": "complete unfiltered run required for a passing gate"})
    for r in rows:
        if r["status"] != "waived" and r["violation"]["severity"] in policy.gate_severities:
            blockers.append({"code": r["status"], "violation_id": r["violation_id"],
                             "message": r["violation"]["rule"]})
    return {"schema_version": 1, "run_id": run.id, "revision": run.revision,
            "scope": run.scope.model_dump(mode="json"), "assessed_on": today.isoformat(),
            "gate_pass": not blockers, "complete": run.complete,
            "counts": dict(Counter(r["status"] for r in rows)),
            "blockers": blockers, "violations": rows, "waivers": outcomes}


def compare_snapshots(old, new) -> dict:
    if old.run.scope != new.run.scope:
        raise ValueError("cannot compare tapeout snapshots across different project/tool/check streams")
    before = {w.id: w for w in old.waivers}
    after = {w.id: w for w in new.waivers}
    old_fp = Counter(fingerprint(v) for v in old.run.violations)
    new_fp = Counter(fingerprint(v) for v in new.run.violations)
    return {"before": old.id, "after": new.id, "before_gate": old.assessment["gate_pass"],
            "after_gate": new.assessment["gate_pass"],
            "waivers_added": sorted(after.keys() - before.keys()),
            "waivers_removed": sorted(before.keys() - after.keys()),
            "waivers_changed": sorted(k for k in before.keys() & after.keys()
                                      if before[k].model_dump() != after[k].model_dump()),
            "occurrences_added": sum((new_fp - old_fp).values()),
            "occurrences_removed": sum((old_fp - new_fp).values()),
            "gate_count_delta": {k: new.assessment["counts"].get(k, 0) - old.assessment["counts"].get(k, 0)
                                 for k in sorted(old.assessment["counts"].keys() | new.assessment["counts"].keys())}}
