"""Bounded candidate retrieval preserving the exact v1 similarity acceptance set.

Indices only choose what to compare; they never authorize suppression. Dense queries
fail closed. Construction is O(W log W); sparse queries avoid whole-rule scans.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from itertools import chain

from .identity import bucket, normalize_path
from .models import Policy, Violation, Waiver


def center(v: Violation) -> tuple[float, float]:
    p = v.geometries[0].points
    # Half before adding avoids overflow for large but finite coordinates.
    return (min(x for x, _ in p) / 2 + max(x for x, _ in p) / 2,
            min(y for _, y in p) / 2 + max(y for _, y in p) / 2)


class CandidateIndex:
    def __init__(self, waivers: list[Waiver], policy: Policy):
        self.policy = policy
        self.objects = defaultdict(list)
        self.sources = defaultdict(list)
        self.geometry = defaultdict(list)
        self.width_n, self.width_d = float(policy.geometry_movement_limit).as_integer_ratio()
        for w in waivers:
            if w.status == "revoked":
                continue
            v, key = w.target, bucket(w.target)
            if v.object_id:
                self.objects[(v.category, v.rule, v.object_id)].append(w)
            if v.path:
                self.sources[(key, normalize_path(v.path))].append(w)
            if v.geometries:
                x, y = center(v)
                self.geometry[(self.geometry_key(v), self.cell(x), self.cell(y))].append(w)
        self.lines = {}
        for key, ws in self.sources.items():
            ws.sort(key=lambda w: (w.target.line or 0, w.id))
            self.lines[key] = [w.target.line or 0 for w in ws]

    def cell(self, value: float) -> int:
        n, d = value.as_integer_ratio()
        return (n * self.width_d) // (d * self.width_n)

    @staticmethod
    def geometry_key(v):
        g = v.geometries[0]
        return (bucket(v), len(v.geometries), g.unit, g.layer, g.frame)

    def _source(self, v):
        key = (bucket(v), normalize_path(v.path))
        lines = self.lines.get(key, [])
        delta, line = self.policy.line_movement_limit, v.line or 0
        lo, hi = bisect_left(lines, line - delta), bisect_right(lines, line + delta)
        for i in range(lo, hi):
            yield self.sources[key][i]

    def _geometry(self, v):
        if not v.geometries:
            return
        x, y = center(v)
        cx, cy = self.cell(x), self.cell(y)
        key = self.geometry_key(v)
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                yield from self.geometry.get((key, cx + dx, cy + dy), ())

    def query(self, v: Violation) -> tuple[list[Waiver], bool]:
        seen = {}
        objects = self.objects.get((v.category, v.rule, v.object_id), ()) if v.object_id else ()
        for w in chain(objects, self._source(v) if v.path else (), self._geometry(v)):
            seen[w.id] = w
            if len(seen) > self.policy.candidate_limit:
                return [], True
        return sorted(seen.values(), key=lambda w: w.id), False
