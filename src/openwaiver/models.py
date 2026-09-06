"""Versioned, strict boundary models. No wildcard waiver targets are supported."""
from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
import re
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator, model_serializer


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, allow_inf_nan=False)


class Category(str, Enum):
    drc = "drc"
    lvs = "lvs"
    erc = "erc"
    lint = "lint"
    cdc = "cdc"
    rdc = "rdc"
    low_power = "low_power"
    coverage = "coverage"
    timing = "timing"


class Severity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"
    critical = "critical"


class Geometry(Model):
    """One ring, box, edge or point, in an explicitly identified local coordinate frame.

    Coordinates are never rounded for identity. Holes/multi-polygons belong in separate
    geometries; parsers must not reduce polygons to bounding boxes for exact matching.
    """
    kind: Literal["polygon", "box", "edge", "point"] = "polygon"
    points: list[tuple[float, float]] = Field(min_length=1, max_length=10000)
    unit: Literal["um", "nm", "dbu"] = "um"
    layer: str = ""
    frame: str = "local"

    @model_validator(mode="after")
    def check_shape(self):
        count = len(self.points)
        if self.kind == "polygon" and count < 3:
            raise ValueError("polygon needs at least three points")
        if self.kind in ("box", "edge") and count != 2:
            raise ValueError("box and edge need exactly two points")
        if self.kind == "point" and count != 1:
            raise ValueError("point needs exactly one coordinate")
        return self


class Violation(Model):
    id: str = ""  # occurrence ID, not an approval or a fingerprint
    category: Category
    rule: str = Field(min_length=1, max_length=500)
    message: str = Field(min_length=1, max_length=20000)
    severity: Severity = Severity.warning
    hierarchy: str = Field(default="", max_length=4000)
    path: str = Field(default="", max_length=4000)
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    object_id: str = Field(default="", max_length=4000)
    geometries: list[Geometry] = Field(default_factory=list, max_length=1000)
    context_hash: str = ""
    multiplicity: int = Field(default=1, ge=1, le=100000000)
    # Opaque adapter data is retained but is not trusted as an approval.
    metadata: dict = Field(default_factory=dict)

    @field_validator("rule", "message")
    @classmethod
    def nonblank(cls, v: str) -> str:
        if not v.strip() or "\x00" in v:
            raise ValueError("required text cannot be blank or contain NUL")
        return v.strip()

    @field_validator("context_hash")
    @classmethod
    def digest(cls, v: str) -> str:
        if v and not re.fullmatch(r"[a-f0-9]{64}", v):
            raise ValueError("context_hash must be a lowercase SHA-256 digest")
        return v

    @model_validator(mode="after")
    def location(self):
        if self.line and not self.path:
            raise ValueError("line requires path")
        if self.column and not self.line:
            raise ValueError("column requires line")
        if not (self.path or self.hierarchy or self.geometries or self.object_id):
            raise ValueError("violation needs a source, hierarchy, geometry or object identity")
        return self


class Scope(Model):
    project: str = Field(min_length=1, max_length=200)
    stream: str = Field(min_length=1, max_length=200)
    tool: str = Field(min_length=1, max_length=200)

    @field_validator("project", "stream", "tool")
    @classmethod
    def clean(cls, v):
        if not v.strip() or any(ord(c) < 32 for c in v):
            raise ValueError("scope must be nonblank printable text")
        return v.strip()


class Run(Model):
    schema_version: Literal[1] = 1
    id: str = Field(default_factory=lambda: uid("run"))
    scope: Scope
    revision: str = Field(min_length=1)
    tool_version: str = ""
    rule_deck_digest: str = ""
    configuration_digest: str = ""
    complete: bool = False
    # A complete category means the full, UNFILTERED check domain, not just violations found.
    checked_categories: list[Category] = Field(default_factory=list)
    source_sha256: str
    format: str
    created_at: datetime = Field(default_factory=utcnow)
    violations: list[Violation] = Field(default_factory=list, max_length=250000)
    physical_manifest: dict | None = None

    @model_serializer(mode="wrap")
    def compatible_dump(self, handler):
        data = handler(self)
        if self.physical_manifest is None:
            data.pop("physical_manifest", None)
        return data

    @model_validator(mode="after")
    def physical_binding(self):
        from .physical import validate_run
        validate_run(self)
        return self

    @model_validator(mode="after")
    def coverage_and_ids(self):
        if self.complete and not self.checked_categories:
            raise ValueError("complete runs require explicit checked_categories")
        if len(set(self.checked_categories)) != len(self.checked_categories):
            raise ValueError("duplicate checked category")
        ids = [v.id for v in self.violations]
        if any(not x for x in ids) or len(set(ids)) != len(ids):
            raise ValueError("each occurrence needs a unique nonempty ID")
        if self.complete and any(v.category not in self.checked_categories for v in self.violations):
            raise ValueError("violation outside the declared complete check coverage")
        return self


class Evidence(Model):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    filename: str = Field(min_length=1, max_length=200)
    size: int = Field(ge=0, le=5 * 1024 * 1024)
    media_type: str


class Approval(Model):
    actor: str
    at: datetime = Field(default_factory=utcnow)
    decision: Literal["approve", "reject"]
    comment: str = Field(min_length=3, max_length=10000)
    content_digest: str


class Waiver(Model):
    schema_version: Literal[1] = 1
    id: str = Field(default_factory=lambda: uid("wvr"))
    version: int = Field(default=1, ge=1)
    scope: Scope
    baseline_run_id: str
    baseline_revision: str
    baseline_provenance: dict[str, str]
    target: Violation
    fingerprint: str
    rationale: str = Field(min_length=12, max_length=20000)
    owner: str = Field(min_length=1, max_length=200)
    reviewers: list[str] = Field(min_length=1, max_length=10)
    expires_on: date | None = None
    valid_revision: str | None = None  # exact revision, NOT ancestry or <= comparison
    tags: list[str] = Field(default_factory=list, max_length=50)
    status: Literal["proposed", "submitted", "approved", "rejected", "revoked"] = "proposed"
    creator: str
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    evidence: list[Evidence] = Field(default_factory=list, max_length=50)
    approvals: list[Approval] = Field(default_factory=list)

    @model_validator(mode="after")
    def bounded_and_independent(self):
        if self.expires_on is None and not self.valid_revision:
            raise ValueError("expiration date or exact valid_revision is required")
        if len(set(self.reviewers)) != len(self.reviewers):
            raise ValueError("reviewers must be distinct")
        if self.owner in self.reviewers or self.creator in self.reviewers:
            raise ValueError("owner and creator cannot review their own waiver")
        if any(not r.strip() for r in self.reviewers) or not self.owner.strip():
            raise ValueError("identities must be nonblank")
        if len(self.rationale.strip()) < 12:
            raise ValueError("rationale must explain the engineering justification")
        return self


class Policy(Model):
    schema_version: Literal[1] = 1
    require_evidence: bool = True
    require_context_across_revisions: bool = True
    max_waiver_days: int = Field(default=90, ge=1, le=3660)
    min_approvals: int = Field(default=1, ge=1, le=10)
    critical_approvals: int = Field(default=2, ge=1, le=10)
    high_risk_categories: list[Category] = Field(
        default_factory=lambda: [Category.cdc, Category.rdc, Category.timing]
    )
    forbidden_rules: list[str] = Field(default_factory=list)
    gate_severities: list[Severity] = Field(
        default_factory=lambda: [Severity.warning, Severity.error, Severity.critical]
    )
    candidate_limit: int = Field(default=256, ge=1, le=10000)
    line_movement_limit: int = Field(default=80, ge=1, le=100000)
    geometry_movement_limit: float = Field(default=100.0, gt=0)

    def quorum(self, w: Waiver) -> int:
        if w.target.category in self.high_risk_categories or w.target.severity == Severity.critical:
            return max(self.min_approvals, self.critical_approvals)
        return self.min_approvals


class Principal(Model):
    name: str = Field(min_length=1)
    role: Literal["viewer", "contributor", "reviewer", "admin"]
    # None is explicitly workspace-wide, including legacy tokens. [] grants nothing.
    projects: list[str] | None = Field(default=None, max_length=1000)

    @field_validator("projects")
    @classmethod
    def project_grants(cls, value):
        if value is not None:
            if len(value) != len(set(value)):
                raise ValueError("duplicate project grant")
            for project in value:
                if (not project.strip() or project != project.strip() or len(project) > 200
                        or any(ord(c) < 32 for c in project)):
                    raise ValueError("invalid project grant")
        return value


class Snapshot(Model):
    schema_version: Literal[1] = 1
    id: str = Field(default_factory=lambda: uid("snap"))
    name: str = Field(min_length=1, max_length=200)
    created_at: datetime = Field(default_factory=utcnow)
    actor: str
    run: Run
    waivers: list[Waiver]
    policy: Policy
    assessment: dict
    audit_head: str
