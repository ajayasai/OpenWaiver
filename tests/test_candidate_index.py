from random import Random
import pytest

from openwaiver.candidate_index import CandidateIndex
from openwaiver.engine import assess
from openwaiver.identity import fingerprint, similarity
from openwaiver.models import Geometry, Policy, utcnow


@pytest.mark.parametrize("seed", range(10))
def test_index_retrieves_every_exhaustive_similarity_match(seed, make_run, make_waiver, record):
    w = make_waiver(make_run())
    rng = Random(seed)
    waivers = []
    for i in range(100):
        x, y = rng.uniform(-500, 500), rng.uniform(-500, 500)
        target = w.target.model_copy(update={"id": str(i), "path": rng.choice(["a.sv", "b.sv", ""]),
            "line": rng.randint(1, 1000), "hierarchy": rng.choice(["top/a", "top/b"]),
            "object_id": rng.choice(["", "object-x", "object-y"]),
            "geometries": [Geometry(kind="box", points=[(x, y), (x + 1, y + 1)])]})
        waivers.append(w.model_copy(update={"id": str(i), "target": target, "fingerprint": fingerprint(target)}))
    policy = Policy(candidate_limit=1000)
    index = CandidateIndex(waivers, policy)
    for _ in range(20):
        v = rng.choice(waivers).target.model_copy(update={"line": rng.randint(1, 1000)})
        pool, overflow = index.query(v)
        assert not overflow
        expected = {a.id for a in waivers if similarity(a.target, v, policy)[0] >= .7}
        assert expected <= {a.id for a in pool}


def test_sparse_same_rule_moved_sources_do_not_hit_global_budget(make_run, make_waiver):
    run = make_run()
    w = make_waiver(run)
    waivers, violations = [], []
    for i in range(2000):
        v = w.target.model_copy(update={"id": str(i), "line": i * 300 + 1})
        waivers.append(w.model_copy(update={"id": str(i), "target": v, "fingerprint": fingerprint(v)}))
        violations.append(v.model_copy(update={"line": v.line + 1}))
    result = assess(run.model_copy(update={"violations": violations}), waivers, Policy(), utcnow().date())
    assert result["counts"] == {"needs_review": 2000}
    assert not result["gate_pass"]  # Retrieval improvements never grant approval.


def test_dense_geometry_remains_ambiguous(make_run, make_waiver):
    run = make_run()
    w = make_waiver(run)
    a = w.target.model_copy(update={"path": "", "line": None, "geometries": [Geometry(kind="point", points=[(0, 0)])]})
    waivers = [w.model_copy(update={"id": str(i), "target": a, "fingerprint": fingerprint(a)}) for i in range(10)]
    moved = a.model_copy(update={"geometries": [Geometry(kind="point", points=[(1, 0)])]})
    result = assess(run.model_copy(update={"violations": [moved]}), waivers, Policy(candidate_limit=2), utcnow().date())
    assert result["counts"] == {"ambiguous": 1}
    assert all(w["status"] == "not_observed" for w in result["waivers"])


def test_extreme_finite_geometry_does_not_overflow_index(make_run, make_waiver):
    w = make_waiver(make_run())
    target = w.target.model_copy(update={"geometries": [Geometry(kind="point", points=[(1e308, -1e308)])]})
    w = w.model_copy(update={"target": target})
    index = CandidateIndex([w], Policy(geometry_movement_limit=1e-300))
    candidates, overflow = index.query(target)
    assert not overflow and candidates[0].id == w.id
