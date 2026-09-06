from copy import deepcopy
from datetime import timedelta
import hashlib
import json
import random

import pytest

from openwaiver.errors import OpenWaiverError
from openwaiver.identity import canonical, fingerprint
from openwaiver.models import Geometry, Run, Scope, Violation, utcnow
from openwaiver.physical import (CONTRACT, Neighborhood, PhysicalManifest, Placement, Polygon,
    Recipe, bind_physical, compare_physical, context_hash, marker, neighborhood_view, ring,
    transform_hash, validate_run)


def fixture():
    v = Violation(id="marker", category="drc", rule="METAL.SPACE", hierarchy="TOP",
        message="Spacing is below the declared minimum", geometries=[
            Geometry(kind="box", unit="dbu", layer="1/0", points=[(0, 0), (20, 30)])])
    recipe = Recipe(top_cell="TOP", dbu_nm="1", layers=["1/0", "2/0"], halo_dbu=500,
                    producer="synthetic-test/1")
    poly = Polygon(layer="2/0", hull=[(50, 0), (90, 0), (90, 50), (50, 50)],
                   holes=[[(60, 10), (70, 10), (70, 20), (60, 20)]])
    n = Neighborhood(shapes=[poly])
    content = canonical({"schema_version": 1, "violations": [v.model_dump(mode="json")]})
    m = PhysicalManifest(scope=Scope(project="chip", tool="klayout", stream="physical"), revision="A",
        report_sha256=hashlib.sha256(content.encode()).hexdigest(), layout_sha256="a" * 64,
        recipe=recipe, targets={v.id: n})
    return v, m, content


def run_for(v, m, revision=None):
    m = m.model_copy(deep=True)
    if revision:
        m.revision = revision
    vs = bind_physical([v], m, m.scope, m.revision, m.report_sha256)
    return Run(scope=m.scope, revision=m.revision, source_sha256=m.report_sha256,
               format="json", violations=vs, complete=True, checked_categories=["drc"],
               physical_manifest=m.model_dump(mode="json"))


@pytest.mark.parametrize("rotation", [0, 90, 180, 270])
@pytest.mark.parametrize("mirror", [False, True])
def test_common_transform_is_advisory_only(rotation, mirror):
    v, m, _ = fixture()
    old = m.targets[v.id]
    t = Placement(rotation=rotation, mirror=mirror, dx=1300, dy=-970)
    n = Neighborhood(placement=t, shapes=[Polygon(layer=p.layer,
        hull=[t.apply(x) for x in p.hull], holes=[[t.apply(x) for x in h] for h in p.holes]) for p in old.shapes])
    assert transform_hash(v, m.recipe, old) == transform_hash(v, m.recipe, n)
    new = m.model_copy(deep=True)
    new.targets[v.id] = n
    before, after = run_for(v, m), run_for(v, new, "B")
    assert fingerprint(before.violations[0]) != fingerprint(after.violations[0])
    result = compare_physical(before, after)
    assert result["approvals_granted"] == 0
    assert result["correspondences"][0]["status"] in ("same_context", "transformed_context")


def test_same_bbox_different_holes_never_equivalent():
    v, m, _ = fixture()
    old = m.targets[v.id]
    new = old.model_copy(deep=True)
    new.shapes[0].holes = []
    assert context_hash(v, m.recipe, old) != context_hash(v, m.recipe, new)
    assert transform_hash(v, m.recipe, old) != transform_hash(v, m.recipe, new)
    new.shapes[0].hull = [(50, 0), (90, 0), (70, 10), (90, 50), (50, 50)]
    assert context_hash(v, m.recipe, old) != context_hash(v, m.recipe, new)


def test_relative_positions_and_duplicate_shapes_are_preserved():
    v, m, _ = fixture()
    old = m.targets[v.id]
    moved = old.model_copy(deep=True)
    moved.shapes[0].hull = [(x + 10, y) for x, y in moved.shapes[0].hull]
    moved.shapes[0].holes = [[(x + 10, y) for x, y in h] for h in moved.shapes[0].holes]
    assert context_hash(v, m.recipe, old) != context_hash(v, m.recipe, moved)
    duplicate = old.model_copy(deep=True)
    duplicate.shapes.append(duplicate.shapes[0].model_copy())
    assert context_hash(v, m.recipe, old) != context_hash(v, m.recipe, duplicate)


def test_seeded_ring_start_winding_and_order_properties():
    # 256 deterministic metamorphic cases, one genuine property test, not inflated test counts.
    rng = random.Random(271828)
    v, m, _ = fixture()
    old = m.targets[v.id]
    expected = context_hash(v, m.recipe, old)
    for _ in range(256):
        new = old.model_copy(deep=True)
        rings = [new.shapes[0].hull, *new.shapes[0].holes]
        for r in rings:
            k = rng.randrange(len(r)); r[:] = r[k:] + r[:k]
            if rng.getrandbits(1): r.reverse()
            if rng.getrandbits(1): r.append(r[0])
        assert context_hash(v, m.recipe, new) == expected


@pytest.mark.parametrize("shape", [[], [(0, 0), (0, 0), (0, 0)], [(0, 0), (1, 1), (2, 2)],
                                  [(0, 0), (0, 0), (1, 1), (0, 1)]])
def test_invalid_rings_rejected(shape):
    with pytest.raises(ValueError): ring(shape)


@pytest.mark.parametrize("value", ["0", "-1", "NaN", "Infinity", "1e99999", "1000001", "1/2", " 1"])
def test_bad_unit_rejected(value):
    _, m, _ = fixture()
    with pytest.raises(ValueError): Recipe.model_validate({**m.recipe.model_dump(), "dbu_nm": value})


@pytest.mark.parametrize("changes", [{"rotation": 45}, {"rotation": True}, {"rotation": "90"},
                                     {"dx": 1.5}, {"dx": True}, {"mirror": 1}, {"dx": 2**51}])
def test_unsupported_placement_rejected(changes):
    with pytest.raises(ValueError): Placement(**changes)


def test_off_grid_and_unknown_frame_rejected():
    v, m, _ = fixture()
    for g in [Geometry(kind="point", points=[(.0005, 0)], unit="um"),
              Geometry(kind="point", points=[(0, 0)], frame="unknown")]:
        with pytest.raises(OpenWaiverError): marker(v.model_copy(update={"geometries": [g]}), m.recipe, Placement())
    with pytest.raises(OpenWaiverError): marker(v.model_copy(update={"multiplicity": 2}), m.recipe, Placement())
    with pytest.raises(OpenWaiverError): marker(v.model_copy(update={"geometries": []}), m.recipe, Placement())
    with pytest.raises(OpenWaiverError): Placement(dx=2**50).apply((1, 0))


def test_unit_spelling_layer_order_equivalence():
    v, m, _ = fixture()
    r = m.recipe.model_copy(update={"dbu_nm": "1.000", "layers": ["2/0", "1/0"]})
    assert context_hash(v, r, m.targets[v.id]) == context_hash(v, m.recipe, m.targets[v.id])
    for unit, factor in [("nm", 1), ("um", .001)]:
        other = v.model_copy(deep=True)
        other.geometries[0].unit = unit
        other.geometries[0].points = [(x * factor, y * factor) for x, y in v.geometries[0].points]
        assert context_hash(other, m.recipe, m.targets[v.id]) == context_hash(v, m.recipe, m.targets[v.id])


@pytest.mark.parametrize("change", ["report", "revision", "scope", "missing", "extra", "hash", "contract"])
def test_binding_rejects_misassociated_evidence(change):
    v, m, _ = fixture()
    args = dict(scope=m.scope, revision=m.revision, report_sha256=m.report_sha256)
    if change == "report": args["report_sha256"] = "b" * 64
    if change == "revision": args["revision"] = "OTHER"
    if change == "scope": args["scope"] = Scope(project="other", tool="klayout", stream="physical")
    if change == "missing": m.targets = {}
    if change == "extra": m.targets["fake"] = m.targets[v.id]
    if change == "hash": v.context_hash = "b" * 64
    if change == "contract": v.metadata[CONTRACT] = {"invented": True}
    with pytest.raises(OpenWaiverError): bind_physical([v], m, **args)


def test_manifest_shape_coverage_and_budgets():
    v, m, _ = fixture()
    d = m.model_dump()
    for mutate in [lambda x: x["recipe"].update(layers=["1/0", "1/0"]),
                   lambda x: x["targets"][v.id]["shapes"][0].update(layer="9/9"),
                   lambda x: x.update(extraction_complete=False),
                   lambda x: x["targets"].update({"": x["targets"][v.id]})]:
        changed = deepcopy(d); mutate(changed)
        with pytest.raises(ValueError): PhysicalManifest.model_validate(changed)
    out = m.targets[v.id].model_copy(deep=True)
    out.shapes[0].hull = [(10000, 0), (10001, 0), (10001, 1)]
    with pytest.raises(OpenWaiverError): context_hash(v, m.recipe, out)


def test_legacy_serialization_stays_byte_compatible():
    v, m, _ = fixture()
    data = dict(scope=m.scope, revision="A", source_sha256="a" * 64, format="json", violations=[v])
    run = Run(**data)
    assert "physical_manifest" not in run.model_dump()
    assert "physical_manifest" not in run.model_dump_json()
    assert canonical(Run.model_validate_json(run.model_dump_json())) == canonical(run)
    d = run.model_dump()
    d["violations"][0]["metadata"][CONTRACT] = {"schema_version": 1}
    with pytest.raises(ValueError): Run.model_validate(d)


def test_stored_manifest_and_hash_cannot_diverge():
    v, m, _ = fixture()
    run = run_for(v, m)
    d = run.model_dump(mode="json")
    d["physical_manifest"]["targets"][v.id]["shapes"][0]["holes"] = []
    with pytest.raises((ValueError, OpenWaiverError)): Run.model_validate(d)
    d = run.model_dump(mode="json"); d["violations"][0]["context_hash"] = ""
    with pytest.raises(ValueError, match="physical context binding"): Run.model_validate(d)
    view = neighborhood_view(run, v.id)
    assert len(view["shapes"][0]["holes"]) == 1
    assert view["layout_sha256"] == "a" * 64
    with pytest.raises(OpenWaiverError): neighborhood_view(run, "missing")


def test_nearby_change_reopens_approved_finding(service, actors):
    v, m, content = fixture()
    def import_one(manifest, revision):
        return service.import_run(actors["alice"], content=content, format="json", scope=m.scope,
            revision=revision, complete=True, checked_categories=["drc"], physical_manifest=manifest.model_dump(mode="json"))
    before = import_one(m, "A")
    w = service.propose(actors["alice"], run_id=before.id, violation_id=v.id, owner="alice", reviewers=["bob"],
        rationale="Synthetic physical evidence reviewed for the bounded exception.", expires_on=utcnow().date()+timedelta(days=20))
    w = service.attach(actors["alice"], w.id, w.version, "physical.json", canonical(m).encode())
    w = service.submit(actors["alice"], w.id, w.version)
    w = service.review(actors["bob"], w.id, w.version, "approve", "Independent physical review.")
    assert service.assessment(before.id)["gate_pass"]
    same = m.model_copy(deep=True); same.revision = "B"; same.layout_sha256 = "b" * 64
    unchanged = import_one(same, "B")
    assert service.assessment(unchanged.id)["gate_pass"]
    changed = m.model_copy(deep=True); changed.revision = "C"; changed.targets[v.id].shapes[0].holes = []
    after = import_one(changed, "C")
    result = service.assessment(after.id)
    assert not result["gate_pass"] and result["counts"] == {"stale": 1}
    assert fingerprint(before.violations[0]) == fingerprint(after.violations[0])
    assert compare_physical(before, after)["counts"] == {"context_changed": 1}
    with service.store.transaction(write=False) as conn: assert service.store.verify(conn)["valid"]


def test_read_only_comparison_rejects_missing_or_cross_project():
    v, m, _ = fixture(); before = run_for(v, m)
    other = before.model_copy(update={"physical_manifest": None})
    with pytest.raises(OpenWaiverError): compare_physical(before, other)
    with pytest.raises(OpenWaiverError): neighborhood_view(other, v.id)
    other = before.model_copy(update={"scope": Scope(project="other", tool="klayout", stream="physical")})
    with pytest.raises(OpenWaiverError): compare_physical(before, other)


def test_ambiguous_replicas_never_become_one_to_one():
    v, m, _ = fixture(); before = run_for(v, m)
    data = before.model_dump()
    other = deepcopy(data["violations"][0]); other["id"] = "replica"
    data["violations"].append(other)
    data["physical_manifest"]["targets"]["replica"] = deepcopy(data["physical_manifest"]["targets"][v.id])
    after = Run.model_validate(data)
    result = compare_physical(before, after)
    assert result["counts"] == {"ambiguous": 2} and result["approvals_granted"] == 0
    assert compare_physical(after, before)["counts"] == {"ambiguous": 1}
