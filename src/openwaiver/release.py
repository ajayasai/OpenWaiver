"""Explicit multi-tool release manifest. A clean single stream cannot stand in for a chip."""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import Field, model_validator

from .engine import assess
from .identity import digest
from .models import Category, Model
from .store import Store


class RequiredCheck(Model):
    stream: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    categories: list[Category] = Field(min_length=1)
    run_id: str | None = None
    tool_version: str = ""
    rule_deck_digest: str = ""
    configuration_digest: str = ""

    @model_validator(mode="after")
    def unique_categories(self):
        if len(self.categories) != len(set(self.categories)):
            raise ValueError("duplicate required category")
        if not self.stream.strip() or not self.tool.strip():
            raise ValueError("stream and tool must not be blank")
        return self


class ReleaseManifest(Model):
    schema_version: int = Field(default=1, ge=1, le=1)
    project: str = Field(min_length=1)
    revision: str = Field(min_length=1)
    max_age_hours: float = Field(default=24, gt=0, le=8760)
    checks: list[RequiredCheck] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_checks(self):
        keys = [(x.stream, x.tool) for x in self.checks]
        if len(keys) != len(set(keys)):
            raise ValueError("each stream/tool must appear once; combine its categories")
        if not self.project.strip() or not self.revision.strip():
            raise ValueError("project and revision must not be blank")
        return self


def gate_release(store: Store, manifest: ReleaseManifest, now: datetime | None = None) -> dict:
    """Assess all manifest streams in one consistent DB read; missing/old/partial fails.

    Runs must be explicitly selected when multiple matching runs exist; no newest-run
    guessing or silent fallback to an older passing run. Age is import age, NOT independently
    attested execution age. The caller must trust its report collection pipeline.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("release assessment requires a timezone-aware timestamp")
    results, blockers = [], []
    with store.transaction(write=False) as conn:
        store.verify(conn)
        policy = store.policy(conn)
        waivers = store.all(conn, "waivers")
        runs = store.all(conn, "runs")
        for check in manifest.checks:
            reasons, result = [], None
            candidates = [r for r in runs if r.scope.project == manifest.project
                          and r.scope.stream == check.stream and r.scope.tool == check.tool
                          and r.revision == manifest.revision]
            if check.run_id:
                candidates = [r for r in candidates if r.id == check.run_id]
            if not candidates:
                reasons.append("required matching run is missing")
            elif len(candidates) != 1:
                reasons.append("multiple matching runs; pin an explicit run_id")
            else:
                run = candidates[0]
                age = (now - run.created_at).total_seconds() / 3600
                if age < 0 or age > manifest.max_age_hours:
                    reasons.append("run import timestamp is future-dated or exceeds freshness bound")
                if not set(check.categories).issubset(run.checked_categories):
                    reasons.append("required checked categories are missing")
                for key in ("tool_version", "rule_deck_digest", "configuration_digest"):
                    expected = getattr(check, key)
                    if expected and expected != getattr(run, key):
                        reasons.append(f"required {key} does not match")
                result = assess(run, waivers, policy, now.date())
                if not result["gate_pass"]:
                    reasons.append("run waiver gate is blocked")
            entry = {"stream": check.stream, "tool": check.tool,
                     "run_id": candidates[0].id if len(candidates) == 1 else None,
                     "gate_pass": not reasons, "reasons": reasons,
                     "counts": result["counts"] if result else {},
                     "blockers": result["blockers"] if result else []}
            results.append(entry)
            if reasons:
                blockers.append({"stream": check.stream, "tool": check.tool, "reasons": reasons})
        return {"schema_version": 1, "project": manifest.project, "revision": manifest.revision,
                "assessed_at": now.isoformat(), "manifest_sha256": digest(manifest),
                "audit_head": store.head(conn), "gate_pass": not blockers,
                "checks": results, "blockers": blockers,
                "caveat": "Only explicitly required manifest checks are covered; not certification of chip signoff."}
