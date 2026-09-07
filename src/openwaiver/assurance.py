"""Versioned, replayable multi-tool release contracts and quantitative waiver budgets.

This supplements (does not silently change) the legacy import-age release gate.
A contract is reviewed separately from run data; every required run is pinned.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .engine import assess
from .errors import IntegrityError
from .execution import HASH, ExecutionReceipt, ReleaseTrust, aware, verify_execution
from .identity import digest, fingerprint
from .models import Category, Model, Policy, Principal, Run, Scope, Waiver, utcnow
from .release import ReleaseManifest


class RiskBudget(Model):
    max_waived_findings: int = Field(default=0, ge=0, le=250000000, strict=True)
    max_by_category: dict[Category, Annotated[int, Field(strict=True, ge=0, le=250000000)]] = Field(default_factory=dict)
    minimum_remaining_days: int = Field(default=0, ge=0, le=3660, strict=True)

    @model_validator(mode="after")
    def category_limits(self):
        # Check before use; bool is not an acceptable numerical risk allowance.
        for value in self.max_by_category.values():
            if type(value) is not int or not 0 <= value <= 250000000:
                raise ValueError("category budget must be a nonnegative integer")
        return self


class ReleaseContract(Model):
    schema_version: Literal[2] = 2
    manifest: ReleaseManifest
    policy_sha256: str = Field(pattern=HASH)
    design_sha256: str = Field(pattern=HASH)
    max_execution_age_hours: float = Field(default=24, gt=0, le=8760)
    budget: RiskBudget = Field(default_factory=RiskBudget)

    @model_validator(mode="after")
    def pinned(self):
        ids = [check.run_id for check in self.manifest.checks]
        if any(not value or not value.strip() for value in ids) or len(set(ids)) != len(ids):
            raise ValueError("release contracts require unique explicit run IDs for every check")
        for check in self.manifest.checks:
            scope = Scope(project=self.manifest.project, stream=check.stream, tool=check.tool)
            if (scope.project, scope.stream, scope.tool) != (self.manifest.project, check.stream, check.tool):
                raise ValueError("contract scopes must be canonical")
            if not check.tool_version.strip():
                raise ValueError("pin a nonempty tool_version for every required check")
            for name in ("rule_deck_digest", "configuration_digest"):
                import re
                if not re.fullmatch(HASH, getattr(check, name)):
                    raise ValueError("pin SHA-256 rule-deck and configuration digests for every check")
        return self


def release_scope(contract, run):
    return any(run.scope == Scope(project=contract.manifest.project, stream=c.stream, tool=c.tool)
               for c in contract.manifest.checks)


def evaluate_contract(contract: ReleaseContract, runs: list[Run], waivers: list[Waiver], policy: Policy,
                      receipts: list[ExecutionReceipt], trust: ReleaseTrust,
                      now: datetime | None = None) -> dict:
    """Pure replay: no writes, network calls, approvals or best-effort run selection."""
    contract = ReleaseContract.model_validate(contract.model_dump(mode="json"))
    trust = ReleaseTrust.model_validate(trust.model_dump(mode="json"))
    policy = Policy.model_validate(policy.model_dump(mode="json"))
    now = aware(now or utcnow())
    runs = [Run.model_validate(r.model_dump(mode="json")) for r in runs]
    waivers = [Waiver.model_validate(w.model_dump(mode="json")) for w in waivers]
    blockers, checks, effective, category_counts = [], [], {}, Counter()

    def block(code, message, **fields):
        blockers.append({"code": code, "message": message, **fields})

    if digest(contract) not in trust.approved_contracts:
        block("contract_unapproved", "contract digest is not independently approved in deployment trust")
    if digest(policy) != contract.policy_sha256:
        block("policy_mismatch", "live policy differs from the independently reviewed contract")
    if len({r.id for r in runs}) != len(runs) or len({w.id for w in waivers}) != len(waivers):
        raise IntegrityError("duplicate run or waiver in release inventory")
    for waiver in waivers:
        if waiver.fingerprint != fingerprint(waiver.target):
            raise IntegrityError("waiver fingerprint differs from its retained target")
    selected = {c.run_id for c in contract.manifest.checks}
    if {r.id for r in runs} - selected:
        raise IntegrityError("release inventory contains unselected runs")
    if any(not release_scope(contract, w) for w in waivers):
        raise IntegrityError("release inventory contains an unrelated waiver scope")
    receipt_map = {}
    for receipt in receipts:
        receipt = ExecutionReceipt.model_validate(receipt.model_dump(mode="json"))
        rid = receipt.claim.run_id
        if rid in receipt_map or rid not in selected:
            raise IntegrityError("duplicate or unselected execution receipt")
        receipt_map[rid] = receipt
    run_map = {r.id: r for r in runs}
    waiver_map = {w.id: w for w in waivers}
    for check in contract.manifest.checks:
        first_blocker = len(blockers)
        run = run_map.get(check.run_id)
        entry = {"stream": check.stream, "tool": check.tool, "run_id": check.run_id,
                 "counts": {}, "producer": None}
        checks.append(entry)
        if run is None:
            block("missing_run", "required pinned run is missing", run_id=check.run_id)
        elif (run.scope != Scope(project=contract.manifest.project, stream=check.stream, tool=check.tool)
              or run.revision != contract.manifest.revision):
            block("run_scope", "run scope or revision differs from the contract", run_id=run.id)
        else:
            age = (now - aware(run.created_at)).total_seconds() / 3600
            if not 0 <= age <= contract.manifest.max_age_hours:
                block("import_age", "run import is future-dated or too old", run_id=run.id)
            if not set(check.categories).issubset(run.checked_categories):
                block("coverage", "required check categories are absent", run_id=run.id)
            for name in ("tool_version", "rule_deck_digest", "configuration_digest"):
                if getattr(check, name) != getattr(run, name):
                    block("provenance", f"pinned {name} differs", run_id=run.id)
            if run.id not in receipt_map:
                block("execution_receipt", "authorized producer receipt is missing", run_id=run.id)
            else:
                try:
                    entry["producer"] = verify_execution(receipt_map[run.id], run, contract.design_sha256,
                                                         trust, now, contract.max_execution_age_hours)
                except (ValueError, IntegrityError) as exc:
                    block("execution_receipt", str(exc), run_id=run.id)
            result = assess(run, waivers, policy, now.date())
            entry["counts"] = result["counts"]
            if not result["gate_pass"]:
                block("waiver_gate", "required stream has unresolved blockers", run_id=run.id,
                      details=result["blockers"])
            for row in result["violations"]:
                if row["status"] != "waived":
                    continue
                category_counts[row["violation"]["category"]] += 1
                for wid in row["waiver_ids"]:
                    w = waiver_map[wid]
                    effective[wid] = w
                    if (not aware(w.created_at) <= aware(w.updated_at) <= now
                            or any(not w.created_at <= aware(a.at) <= w.updated_at for a in w.approvals)):
                        block("review_chronology", "approval history is inconsistent with the assessment time",
                              run_id=run.id, waiver_id=wid)
                    if (any(a.decision != "approve" for a in w.approvals)
                            or len({a.actor for a in w.approvals}) != len(w.approvals)):
                        block("review_history", "approved record contains a rejection or duplicate reviewer decision",
                              run_id=run.id, waiver_id=wid)
                    if w.expires_on and (w.expires_on - now.date()).days < contract.budget.minimum_remaining_days:
                        block("expiry_horizon", "waiver expires inside the release protection window",
                              run_id=run.id, waiver_id=wid)
        entry["blockers"] = blockers[first_blocker:]
        entry["gate_pass"] = not entry["blockers"]
    total = sum(category_counts.values())
    if total > contract.budget.max_waived_findings:
        block("waiver_budget", "total waived findings exceed the reviewed budget",
              actual=total, maximum=contract.budget.max_waived_findings)
    for category, maximum in sorted(contract.budget.max_by_category.items()):
        actual = category_counts[category.value]
        if actual > maximum:
            block("category_budget", "category waived findings exceed the reviewed budget",
                  category=category.value, actual=actual, maximum=maximum)
    return {"schema_version": 2, "contract_sha256": digest(contract),
            "project": contract.manifest.project, "revision": contract.manifest.revision,
            "assessed_at": now.isoformat(), "gate_pass": not blockers, "checks": checks,
            "blockers": blockers, "risk": {"waived_findings": total,
                "by_category": dict(sorted(category_counts.items())),
                "effective_waivers": sorted(effective), "budget": contract.budget.model_dump(mode="json")},
            "notice": "Only the reviewed contract's checks are covered. Producer claims require a trusted pipeline; this is not chip signoff certification."}


def capture_inventory(service, contract: ReleaseContract, actor: Principal | None = None, *, include_evidence: bool = False) -> dict:
    """One verified read transaction; never return unrelated projects or ledger history."""
    contract = ReleaseContract.model_validate(contract.model_dump(mode="json"))
    if actor is not None:
        service.project(actor, contract.manifest.project)
    selected = {c.run_id for c in contract.manifest.checks}
    with service.store.transaction(write=False) as conn:
        service.store.verify(conn)
        runs = [r for r in service.store.all(conn, "runs") if r.id in selected]
        # A guessed foreign ID must not reveal its existence, contents, or provenance.
        if actor is not None:
            runs = [r for r in runs if service.visible(actor, r)]
        waivers = [w for w in service.store.all(conn, "waivers") if release_scope(contract, w)]
        result = {"runs": sorted(runs, key=lambda r: r.id), "waivers": sorted(waivers, key=lambda w: w.id),
                  "policy": service.store.policy(conn)}
        if include_evidence:
            references = {e.sha256 for w in waivers for e in w.evidence}
            result["evidence"] = {sha: conn.execute("SELECT data FROM evidence WHERE sha256=?", (sha,)).fetchone()[0]
                                  for sha in sorted(references)}
        return result
