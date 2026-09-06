"""Exact, bounded physical-context evidence and non-authoritative review matching.

All coordinates use integer database units. Polygon holes and duplicate shapes are
retained. No bbox, float tolerance, or per-shape normalization grants an approval.
A manifest describes the declared layers/window, not electrical connectivity or a
foundry-approved waiver. Native extraction lives in physical_native.py.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, StrictInt, field_validator, model_validator

from .errors import OpenWaiverError
from .identity import canonical, digest
from .models import Model, Scope, Violation

CONTRACT = "openwaiver_physical_contract"
Coord = Annotated[StrictInt, Field(ge=-(2**50), le=2**50)]
Point = tuple[Coord, Coord]
MAX_VERTICES = 250000


class Placement(Model):
    """Mirror around local x axis, rotate counterclockwise, then translate."""
    rotation: Literal[0, 90, 180, 270] = 0
    mirror: bool = Field(default=False, strict=True)
    dx: Coord = 0
    dy: Coord = 0

    @field_validator("rotation", mode="before")
    @classmethod
    def integer_angle(cls, value):
        if type(value) is not int:
            raise ValueError("rotation must be an integer multiple of 90 degrees")
        return value

    def apply(self, point: tuple[int, int]) -> tuple[int, int]:
        x, y = point
        if self.mirror:
            y = -y
        for _ in range(self.rotation // 90):
            x, y = -y, x
        result = x + self.dx, y + self.dy
        if any(abs(n) > 2**50 for n in result):
            raise OpenWaiverError("transformed coordinate budget exceeded")
        return result


def ring(points: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Canonical winding/start vertex in linear time; never reorder the polygon."""
    p = list(points)
    if len(p) > 1 and p[0] == p[-1]:
        p.pop()
    if len(p) < 3 or len(set(p)) < 3:
        raise ValueError("a ring needs at least three distinct vertices")
    if any(p[i] == p[(i + 1) % len(p)] for i in range(len(p))):
        raise ValueError("zero-length polygon edge")
    if sum(x * p[(i + 1) % len(p)][1] - y * p[(i + 1) % len(p)][0]
           for i, (x, y) in enumerate(p)) == 0:
        raise ValueError("zero signed-area polygon ring")

    def least(seq):
        n, i, j, k = len(seq), 0, 1, 0
        doubled = seq + seq
        while i < n and j < n and k < n:
            a, b = doubled[i + k], doubled[j + k]
            if a == b:
                k += 1
            else:
                if a > b:
                    i += k + 1
                    if i == j:
                        i += 1
                else:
                    j += k + 1
                    if i == j:
                        j += 1
                k = 0
        start = min(i, j)
        return doubled[start:start + n]

    return min(least(p), least(list(reversed(p))))


class Polygon(Model):
    layer: str = Field(min_length=1, max_length=200)
    hull: list[Point] = Field(min_length=3, max_length=4096)
    holes: list[Annotated[list[Point], Field(min_length=3, max_length=4096)]] = Field(
        default_factory=list, max_length=256)
    # Values are canonical JSON strings so native property types cannot collapse.
    properties: dict[str, str] = Field(default_factory=dict, max_length=128)

    @model_validator(mode="after")
    def rings(self):
        if len(self.hull) + sum(map(len, self.holes)) > 8192:
            raise ValueError("polygon vertex budget exceeded")
        ring(self.hull)
        for hole in self.holes:
            ring(hole)
        return self


class Recipe(Model):
    top_cell: str = Field(min_length=1, max_length=1000)
    dbu_nm: str = Field(min_length=1, max_length=40)
    layers: list[str] = Field(min_length=1, max_length=128)
    halo_dbu: Annotated[StrictInt, Field(gt=0, le=1000000000)]
    producer: str = Field(min_length=1, max_length=200)
    semantics: Literal["whole-polygons-touching-window-v1"] = "whole-polygons-touching-window-v1"

    @field_validator("dbu_nm")
    @classmethod
    def exact_unit(cls, value):
        # No float parsing, NaN, Infinity, exponents with unbounded integer size, or rounding.
        import re
        if not re.fullmatch(r"\d{1,18}(?:\.\d{1,18})?", value):
            raise ValueError("dbu_nm must be a bounded positive decimal string")
        scale = Fraction(value)
        if scale <= 0 or scale > 1000000:
            raise ValueError("invalid database unit")
        return value

    @model_validator(mode="after")
    def unique_layers(self):
        if len(self.layers) != len(set(self.layers)) or any(not x.strip() for x in self.layers):
            raise ValueError("layers must be nonblank and unique")
        return self

    def identity(self):
        unit = Fraction(self.dbu_nm)
        return {**self.model_dump(), "layers": sorted(self.layers),
                "dbu_nm": [unit.numerator, unit.denominator]}


class Neighborhood(Model):
    placement: Placement = Field(default_factory=Placement)
    shapes: list[Polygon] = Field(default_factory=list, max_length=10000)


class PhysicalManifest(Model):
    schema_version: Literal[1] = 1
    scope: Scope
    revision: str = Field(min_length=1, max_length=1000)
    report_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    layout_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    recipe: Recipe
    # This asserts complete extraction of the declared window/layers only.
    extraction_complete: Literal[True] = True
    targets: dict[str, Neighborhood] = Field(default_factory=dict, max_length=10000)

    @model_validator(mode="after")
    def bounded(self):
        count = 0
        for name, item in self.targets.items():
            if not name or len(name) > 1000:
                raise ValueError("invalid physical occurrence ID")
            for shape in item.shapes:
                if shape.layer not in self.recipe.layers:
                    raise ValueError("shape outside declared layer coverage")
                count += len(shape.hull) + sum(map(len, shape.holes))
                if count > MAX_VERTICES:
                    raise ValueError("manifest vertex budget exceeded; split the check stream")
        return self


def _integer(value: float, unit: str, recipe: Recipe) -> int:
    scale = {"um": Fraction(1000), "nm": Fraction(1), "dbu": Fraction(recipe.dbu_nm)}[unit]
    number = Fraction(str(value)) * scale / Fraction(recipe.dbu_nm)
    if number.denominator != 1 or abs(number) > 2**50:
        raise OpenWaiverError("marker is off the exact database grid or outside coordinate budget")
    return int(number)


def marker(v: Violation, recipe: Recipe, placement: Placement) -> list[dict]:
    if not v.geometries or v.multiplicity != 1:
        raise OpenWaiverError("physical evidence requires a geometric, instance-level finding")
    result = []
    for g in v.geometries:
        if g.frame != "local":
            raise OpenWaiverError("unknown marker frame; supply local geometry and an explicit placement")
        points = [placement.apply((_integer(x, g.unit, recipe), _integer(y, g.unit, recipe)))
                  for x, y in g.points]
        if g.kind == "box":
            xs, ys = zip(*points)
            x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
            points = [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
        result.append({"kind": "polygon" if g.kind == "box" else g.kind,
                       "layer": g.layer, "points": points})
    return result


def bounds(points):
    xs, ys = zip(*points)
    return min(xs), min(ys), max(xs), max(ys)


def window(markers: list[dict], halo: int):
    x0, y0, x1, y1 = bounds([p for m in markers for p in m["points"]])
    return x0 - halo, y0 - halo, x1 + halo, y1 + halo


def touches(a, b):
    return a[0] <= b[2] and a[2] >= b[0] and a[1] <= b[3] and a[3] >= b[1]


def _payload(v: Violation, recipe: Recipe, neighborhood: Neighborhood,
             orientation: Placement | None = None):
    markers = marker(v, recipe, neighborhood.placement)
    region = window(markers, recipe.halo_dbu)
    for shape in neighborhood.shapes:
        if not touches(bounds(shape.hull), region):
            raise OpenWaiverError("declared context shape does not touch the marker window")
    transform = orientation or Placement()
    transformed = [{**m, "points": [transform.apply(p) for p in m["points"]]} for m in markers]
    x0, y0, _, _ = bounds([p for m in transformed for p in m["points"]])

    def relative(points):
        return [(x - x0, y - y0) for x, y in map(transform.apply, points)]

    def marker_points(m):
        p = [(x - x0, y - y0) for x, y in m["points"]]
        return ring(p) if m["kind"] == "polygon" else sorted(p)

    shapes = [{"layer": p.layer, "hull": ring(relative(p.hull)),
               "holes": sorted([ring(relative(h)) for h in p.holes], key=canonical),
               "properties": p.properties} for p in neighborhood.shapes]
    return {"domain": "openwaiver.physical-context.v1", "recipe": recipe.identity(),
            "markers": sorted([{**m, "points": marker_points(m)} for m in transformed], key=canonical),
            "shapes": sorted(shapes, key=canonical)}


def context_hash(v: Violation, recipe: Recipe, neighborhood: Neighborhood) -> str:
    return digest(_payload(v, recipe, neighborhood))


def transform_hash(v: Violation, recipe: Recipe, neighborhood: Neighborhood) -> str:
    """Advisory only. Apply ONE common transform to ALL markers and neighboring shapes."""
    return digest(min((canonical(_payload(v, recipe, neighborhood, Placement(rotation=r, mirror=m)))
                       for r in (0, 90, 180, 270) for m in (False, True))))


def contract(recipe: Recipe, neighborhood: Neighborhood) -> dict:
    # Location/orientation changes remain distinct identities even when context is congruent.
    return {"schema_version": 1, "recipe_sha256": digest(recipe.identity()),
            "placement": neighborhood.placement.model_dump()}


def bind_physical(violations: list[Violation], manifest: PhysicalManifest, scope: Scope,
                  revision: str, report_sha256: str, *, verify: bool = False) -> list[Violation]:
    if (manifest.scope != scope or manifest.revision != revision
            or manifest.report_sha256 != report_sha256):
        raise OpenWaiverError("physical evidence does not match report, scope, or revision")
    if set(manifest.targets) != {v.id for v in violations}:
        raise OpenWaiverError("physical evidence must cover exactly every imported occurrence")
    result = []
    for v in violations:
        neighborhood = manifest.targets[v.id]
        expected, binding = context_hash(v, manifest.recipe, neighborhood), contract(manifest.recipe, neighborhood)
        if v.context_hash and v.context_hash != expected:
            raise OpenWaiverError("reported context hash disagrees with physical evidence")
        if CONTRACT in v.metadata and v.metadata[CONTRACT] != binding:
            raise OpenWaiverError("physical identity contract mismatch")
        if verify and (v.context_hash != expected or v.metadata.get(CONTRACT) != binding):
            raise OpenWaiverError("stored physical context binding is missing or inconsistent")
        result.append(Violation.model_validate({**v.model_dump(), "context_hash": expected,
                      "metadata": {**v.metadata, CONTRACT: binding}}))
    return result


def validate_run(run) -> None:
    if run.physical_manifest is None:
        if any(CONTRACT in v.metadata for v in run.violations):
            raise ValueError("physical contract requires retained physical evidence")
        return
    manifest = PhysicalManifest.model_validate(run.physical_manifest)
    bind_physical(run.violations, manifest, run.scope, run.revision, run.source_sha256, verify=True)


def compare_physical(before, after) -> dict:
    """One-to-one context correspondence for human review. Never changes a waiver."""
    if before.scope != after.scope:
        raise OpenWaiverError("physical comparisons require the same project/tool/stream")
    if before.physical_manifest is None or after.physical_manifest is None:
        raise OpenWaiverError("both runs require retained physical evidence")
    validate_run(before)
    validate_run(after)
    old = PhysicalManifest.model_validate(before.physical_manifest)
    new = PhysicalManifest.model_validate(after.physical_manifest)
    index = defaultdict(list)

    def key(v, manifest):
        return (v.category, v.rule, v.severity, transform_hash(v, manifest.recipe, manifest.targets[v.id]))

    for v in before.violations:
        index[key(v, old)].append(v)
    rows = []
    old_by_id = {v.id: v for v in before.violations}
    for v in after.violations:
        hits = index.get(key(v, new), [])
        exact = [h for h in hits if h.context_hash == v.context_hash]
        state = "no_correspondence"
        if hits:
            state = "ambiguous" if len(hits) != 1 else "same_context" if exact else "transformed_context"
        elif v.id in old_by_id:
            state = "context_changed"
        rows.append({"after_id": v.id, "before_ids": [h.id for h in hits[:128]],
                     "candidate_count": len(hits), "details_truncated": len(hits) > 128,
                     "status": state, "auto_approved": False})
    uses = Counter(i for row in rows for i in row["before_ids"])
    for row in rows:
        if any(uses[i] > 1 for i in row["before_ids"]):
            row["status"] = "ambiguous"
    return {"schema_version": 1, "before_run": before.id, "after_run": after.id,
            "advisory_only": True, "approvals_granted": 0,
            "counts": dict(Counter(r["status"] for r in rows)), "correspondences": rows,
            "limitations": "Declared layers and windows only; no electrical connectivity inference or waiver transfer."}


def neighborhood_view(run, occurrence_id: str) -> dict:
    if run.physical_manifest is None:
        raise OpenWaiverError("run has no physical evidence")
    manifest = PhysicalManifest.model_validate(run.physical_manifest)
    v = next((x for x in run.violations if x.id == occurrence_id), None)
    if v is None:
        raise OpenWaiverError("occurrence not in selected run")
    n = manifest.targets[v.id]
    return {"run_id": run.id, "occurrence_id": v.id, "rule": v.rule,
            "recipe": manifest.recipe.model_dump(), "context_sha256": v.context_hash,
            "layout_sha256": manifest.layout_sha256, "placement": n.placement.model_dump(),
            "markers": marker(v, manifest.recipe, n.placement),
            "window": window(marker(v, manifest.recipe, n.placement), manifest.recipe.halo_dbu),
            "shapes": [s.model_dump() for s in n.shapes], "advisory_only": True}
