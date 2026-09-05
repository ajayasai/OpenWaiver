"""Git-reviewable, all-or-nothing proposal/amendment plans. Never batch approvals."""
from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .engine import provenance
from .errors import Conflict, Forbidden, OpenWaiverError
from .identity import digest, fingerprint
from .models import Model, Principal, Waiver, utcnow


class ProposeOperation(Model):
    action: Literal["propose"] = "propose"
    run_id: str
    violation_id: str
    expected_fingerprint: str
    rationale: str
    owner: str
    reviewers: list[str]
    expires_on: date | None = None
    valid_revision: str | None = None
    tags: list[str] = Field(default_factory=list)


class AmendOperation(Model):
    action: Literal["amend"] = "amend"
    waiver_id: str
    version: int = Field(ge=1)
    expected_content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    changes: dict


class ReviewPlan(Model):
    schema_version: Literal[1] = 1
    project: str = Field(min_length=1, max_length=200)
    created_at: datetime
    expected_audit_head: str = Field(pattern=r"^[a-f0-9]{64}$")
    note: str = Field(min_length=12, max_length=20000)
    operations: list[Annotated[ProposeOperation | AmendOperation, Field(discriminator="action")]] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def aware(self):
        if self.created_at.tzinfo is None:
            raise ValueError("plan created_at requires a timezone")
        return self


def _prepare(service, conn, actor: Principal, plan: ReviewPlan):
    service.role(actor, "contributor", "reviewer", "admin")
    service.project(actor, plan.project)
    service.store.verify(conn)
    if service.store.head(conn) != plan.expected_audit_head:
        raise Conflict("workspace changed since plan creation; regenerate and review the plan")
    if plan.created_at > utcnow():
        raise OpenWaiverError("plan is future-dated")
    policy = service.store.policy(conn)
    existing = service.store.all(conn, "waivers")
    targets = {(w.scope.project, w.scope.stream, w.scope.tool, w.fingerprint)
               for w in existing if w.status != "revoked"}
    prepared, changes, touched = [], [], set()
    plan_id = digest({"plan": plan.model_dump(mode="json"), "actor": actor.name})
    for index, operation in enumerate(plan.operations):
        if isinstance(operation, ProposeOperation):
            run = service.read(conn, "runs", operation.run_id, actor)
            if run.scope.project != plan.project:
                raise OpenWaiverError("all operations must remain within the plan project")
            target = next((v for v in run.violations if v.id == operation.violation_id), None)
            if target is None or fingerprint(target) != operation.expected_fingerprint:
                raise Conflict("target identity changed or does not exist")
            if actor.role != "admin" and operation.owner != actor.name:
                raise Forbidden("contributors must own their proposals")
            key = (run.scope.project, run.scope.stream, run.scope.tool, fingerprint(target))
            if key in targets:
                raise Conflict("duplicate proposal target in plan or existing register")
            targets.add(key)
            w = Waiver(id="wvr_" + digest([plan_id, index])[:32], scope=run.scope,
                baseline_run_id=run.id, baseline_revision=run.revision,
                baseline_provenance=provenance(run), target=target, fingerprint=fingerprint(target),
                rationale=operation.rationale, owner=operation.owner, reviewers=operation.reviewers,
                expires_on=operation.expires_on, valid_revision=operation.valid_revision,
                tags=operation.tags, creator=actor.name, created_at=plan.created_at, updated_at=plan.created_at)
            create, before = True, None
        else:
            if operation.waiver_id in touched:
                raise Conflict("a waiver may only be amended once in a plan")
            touched.add(operation.waiver_id)
            old = service._load(conn, operation.waiver_id, operation.version, actor)
            if old.scope.project != plan.project:
                raise OpenWaiverError("all operations must remain within the plan project")
            service.owner(actor, old)
            if old.status == "revoked":
                raise Conflict("revocation is terminal")
            if digest(old) != operation.expected_content_digest:
                raise Conflict("reviewed waiver content changed")
            allowed = {"rationale", "owner", "reviewers", "expires_on", "valid_revision", "tags"}
            if not operation.changes or set(operation.changes) - allowed:
                raise OpenWaiverError("plan amendments cannot set targets, status, evidence or approvals")
            w = Waiver.model_validate({**old.model_dump(), **operation.changes,
                                      "status": "proposed", "approvals": []})
            create, before = False, old
        service._check_bounds(w, policy)
        prepared.append((create, w))
        changes.append({"action": operation.action, "waiver_id": w.id,
                        "rule": w.target.rule, "violation_id": w.target.id,
                        "scope": w.scope.model_dump(), "before_status": before.status if before else None,
                        "after_status": "proposed", "approvals_removed": len(before.approvals) if before else 0,
                        "before_digest": digest(before) if before else None,
                        "proposed_digest": digest(w)})
    preview = {"schema_version": 1, "project": plan.project, "actor": actor.name,
               "expected_audit_head": plan.expected_audit_head, "changes": changes,
               "approvals_granted": 0, "note": plan.note}
    preview["preview_digest"] = digest({"plan": plan.model_dump(mode="json"), "preview": preview})
    return preview, prepared


def preview_plan(service, actor: Principal, plan: ReviewPlan) -> dict:
    with service.store.transaction(write=False) as conn:
        preview, _ = _prepare(service, conn, actor, plan)
        return preview


def apply_plan(service, actor: Principal, plan: ReviewPlan, expected_digest: str) -> dict:
    with service.store.transaction() as conn:
        preview, prepared = _prepare(service, conn, actor, plan)
        if expected_digest != preview["preview_digest"]:
            raise Conflict("plan or reviewer identity changed after preview")
        results = []
        # No state changes until EVERY operation, scope, version and digest was checked.
        for create, w in prepared:
            action = "git-plan:propose" if create else "git-plan:amend:approval-reset"
            if create:
                service.store.save(conn, "waivers", w, actor.name, action, create=True)
            else:
                w = service._save(conn, actor, w, action)
            results.append({"waiver_id": w.id, "version": w.version, "status": w.status})
        return {"applied": True, "preview_digest": expected_digest, "approvals_granted": 0,
                "audit_head": service.store.head(conn), "results": results}


def proposal_template(service, actor: Principal, run_id: str, violation_ids: list[str],
                      rationale: str, reviewers: list[str], expires_on: date | None = None,
                      valid_revision: str | None = None) -> ReviewPlan:
    service.role(actor, "contributor", "reviewer", "admin")
    if not 1 <= len(violation_ids) <= 1000 or len(set(violation_ids)) != len(violation_ids):
        raise OpenWaiverError("select 1..1000 distinct occurrence IDs")
    with service.store.transaction(write=False) as conn:
        service.store.verify(conn)
        run = service.read(conn, "runs", run_id, actor)
        selected = {v.id: v for v in run.violations}
        if not set(violation_ids) <= selected.keys():
            raise OpenWaiverError("selected occurrence is missing from the run")
        plan = ReviewPlan(project=run.scope.project, created_at=utcnow(),
            expected_audit_head=service.store.head(conn), note=rationale,
            operations=[ProposeOperation(run_id=run.id, violation_id=id,
                expected_fingerprint=fingerprint(selected[id]), rationale=rationale,
                owner=actor.name, reviewers=reviewers, expires_on=expires_on,
                valid_revision=valid_revision) for id in violation_ids])
        _prepare(service, conn, actor, plan)
        return plan
