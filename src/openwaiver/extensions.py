"""Project-aware API routes for review plans and explicit dependency comparisons."""
from __future__ import annotations

from datetime import date
import yaml
from fastapi import Depends
from pydantic import Field

from .context import ContextManifest, compare_context
from .interchange import load_yaml
from .models import Model, Principal
from .plans import ReviewPlan, apply_plan, preview_plan, proposal_template


class PlanText(Model):
    yaml: str = Field(min_length=1, max_length=4 * 1024 * 1024)


class ApplyPlanText(PlanText):
    expected_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class TemplateRequest(Model):
    run_id: str
    violation_ids: list[str] = Field(min_length=1, max_length=1000)
    rationale: str
    reviewers: list[str]
    expires_on: date | None = None
    valid_revision: str | None = None


class ContextComparison(Model):
    before: ContextManifest
    after: ContextManifest


def register_routes(app, service, principal):
    @app.post("/api/review-plans/template")
    def template(body: TemplateRequest, actor: Principal = Depends(principal)):
        plan = proposal_template(service, actor, **body.model_dump())
        return {"yaml": yaml.safe_dump(plan.model_dump(mode="json"), sort_keys=False, allow_unicode=True)}

    @app.post("/api/review-plans/preview")
    def preview(body: PlanText, actor: Principal = Depends(principal)):
        return preview_plan(service, actor, ReviewPlan.model_validate(load_yaml(body.yaml)))

    @app.post("/api/review-plans/apply")
    def apply(body: ApplyPlanText, actor: Principal = Depends(principal)):
        return apply_plan(service, actor, ReviewPlan.model_validate(load_yaml(body.yaml)), body.expected_digest)

    @app.post("/api/contexts/compare")
    def context_comparison(body: ContextComparison, actor: Principal = Depends(principal)):
        service.project(actor, body.before.scope.project)
        service.project(actor, body.after.scope.project)
        return compare_context(body.before, body.after)
