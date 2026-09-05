"""Conservative exact identity and explicitly non-authoritative candidate similarity."""
from __future__ import annotations

from difflib import SequenceMatcher
import hashlib
import json
import math
import posixpath

from .models import Geometry, Policy, Violation, Waiver


def canonical(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def normalize_path(path: str) -> str:
    # Never lowercase, remove directory components or guess an absolute workspace root.
    return posixpath.normpath(path.replace("\\", "/")) if path else ""


def text(s: str) -> str:
    # Keep identifiers, numbers, case and hierarchy separators: they may be semantically significant.
    return " ".join(s.split())


def points(g: Geometry, relative: bool = False) -> list[tuple[float, float]]:
    p = [(0.0 if x == 0 else x, 0.0 if y == 0 else y) for x, y in g.points]
    if relative:
        x0, y0 = min(x for x, _ in p), min(y for _, y in p)
        p = [(x - x0, y - y0) for x, y in p]
    if g.kind == "polygon":
        if len(p) > 1 and p[0] == p[-1]:
            p = p[:-1]
        def least_rotation(ring):
            # Booth's algorithm: linear time even for many repeated vertices.
            n = len(ring)
            doubled = ring + ring
            i, j, k = 0, 1, 0
            while i < n and j < n and k < n:
                a, b = doubled[i + k], doubled[j + k]
                if a == b:
                    k += 1
                    continue
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
        return min(least_rotation(p), least_rotation(list(reversed(p))))
    if g.kind == "box":
        return [(min(x for x, _ in p), min(y for _, y in p)),
                (max(x for x, _ in p), max(y for _, y in p))]
    if g.kind == "edge":
        return sorted(p)
    return p


def geometry_identity(g: Geometry, relative: bool = False):
    return {"kind": g.kind, "unit": g.unit, "layer": g.layer, "frame": g.frame,
            "points": points(g, relative)}


def fingerprint(v: Violation) -> str:
    return "ow1:" + digest({
        "category": v.category.value, "rule": v.rule, "hierarchy": v.hierarchy.strip(),
        "path": normalize_path(v.path), "line": v.line, "column": v.column,
        "object_id": v.object_id, "message": v.message.replace("\r\n", "\n"), "severity": v.severity.value,
        "metadata": v.metadata,
        "multiplicity": v.multiplicity,
        "geometries": sorted([geometry_identity(g) for g in v.geometries], key=canonical),
    })


def approval_digest(w: Waiver) -> str:
    d = w.model_dump(mode="json")
    for key in ("version", "updated_at", "status", "approvals"):
        d.pop(key)
    return digest(d)


def bucket(v: Violation) -> tuple:
    return (v.category.value, v.rule, v.hierarchy)


def similarity(old: Violation, new: Violation, policy: Policy) -> tuple[float, list[str]]:
    """Suggestions only. A score never grants a waiver, even at 1.0."""
    if old.category != new.category or old.rule != new.rule:
        return 0.0, []
    if old.object_id and old.object_id == new.object_id:
        return 0.99, ["stable object ID; details changed"]
    if old.hierarchy != new.hierarchy:
        return 0.0, []
    if old.geometries and new.geometries and len(old.geometries) == len(new.geometries):
        a, b = old.geometries[0], new.geometries[0]
        if (a.unit, a.layer, a.frame) != (b.unit, b.layer, b.frame):
            return 0.0, []
        ax = [p[0] for p in a.points]
        ay = [p[1] for p in a.points]
        bx = [p[0] for p in b.points]
        by = [p[1] for p in b.points]
        distance = math.hypot((max(ax) / 2 + min(ax) / 2) - (max(bx) / 2 + min(bx) / 2),
                              (max(ay) / 2 + min(ay) / 2) - (max(by) / 2 + min(by) / 2))
        if distance > policy.geometry_movement_limit:
            return 0.0, []
        if all(geometry_identity(x, True) == geometry_identity(y, True)
               for x, y in zip(old.geometries, new.geometries)):
            return 0.95, ["geometry moved", f"centroid displacement {distance:.6g} {a.unit}"]
        ix = max(0, min(max(ax), max(bx)) - max(min(ax), min(bx)))
        iy = max(0, min(max(ay), max(by)) - max(min(ay), min(by)))
        aa = (max(ax) - min(ax)) * (max(ay) - min(ay))
        ba = (max(bx) - min(bx)) * (max(by) - min(by))
        union = aa + ba - ix * iy
        iou = ix * iy / union if union else 0
        if iou >= .2:
            return .7 + .2 * iou, ["geometry reshaped", f"bounding-box overlap {iou:.3f}"]
    if old.path and normalize_path(old.path) == normalize_path(new.path):
        delta = abs((old.line or 0) - (new.line or 0))
        if delta <= policy.line_movement_limit:
            if text(old.message) == text(new.message):
                return .94, ["source location or other details changed", f"line delta {delta}"]
            ratio = SequenceMatcher(None, text(old.message), text(new.message), autojunk=False).ratio()
            if ratio >= .72:
                return .7 + .15 * ratio, ["message changed", f"text similarity {ratio:.3f}"]
    return 0.0, []
