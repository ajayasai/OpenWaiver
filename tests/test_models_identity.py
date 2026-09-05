import math
import random

import pytest
from pydantic import ValidationError

from openwaiver.identity import fingerprint, geometry_identity, normalize_path, points
from openwaiver.models import Category, Geometry, Violation


@pytest.mark.parametrize("category", list(Category))
def test_all_check_domains(record, category):
    assert Violation(**{**record, "category": category}).category == category


@pytest.mark.parametrize("change", [
    {"rule": ""}, {"message": " "}, {"category": "unknown"}, {"severity": "high"},
    {"line": 0}, {"column": 0}, {"multiplicity": 0}, {"context_hash": "not-a-hash"},
    {"extra": 1}, {"path": "", "line": 1}, {"path": "", "line": None, "column": 2},
])
def test_invalid_fields(record, change):
    with pytest.raises(ValidationError):
        Violation(**{**record, **change})


def test_location_required():
    with pytest.raises(ValidationError):
        Violation(category="lint", rule="R", message="Finding")


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_finite_geometry(bad):
    with pytest.raises(ValidationError):
        Geometry(kind="point", points=[(bad, 0)])


@pytest.mark.parametrize("key,value", [("rule", "WIDTH2"), ("hierarchy", "top/u2"),
    ("path", "rtl/other.sv"), ("line", 22), ("column", 3), ("severity", "error"),
    ("message", "Signal has width 64, expected 16"), ("object_id", "net_2"),
    ("multiplicity", 2), ("metadata", {"endLine": 99})])
def test_semantic_changes_break_identity(record, key, value):
    assert fingerprint(Violation(**record)) != fingerprint(Violation(**{**record,key:value}))


def test_context_separate_from_identity(record):
    assert fingerprint(Violation(**record)) == fingerprint(Violation(**{**record,"context_hash":"a"*64}))


def test_occurrence_id_not_semantic(record):
    assert fingerprint(Violation(**record)) == fingerprint(Violation(**{**record,"id":"another-row"}))


def test_literal_spaces_are_not_erased(record):
    a=Violation(**{**record,"message":'Signal "a  b" differs'})
    b=Violation(**{**record,"message":'Signal "a b" differs'})
    assert fingerprint(a) != fingerprint(b)


def test_no_basename_or_case_folding():
    assert normalize_path("rtl\\top.sv") == "rtl/top.sv"
    assert normalize_path("a/top.sv") != normalize_path("b/top.sv")
    assert normalize_path("A.sv") != normalize_path("a.sv")


def test_polygon_rotation_reversal_closure_invariant():
    ring=[(0,0),(2,0),(2,2),(1,3),(0,2)]
    reference=geometry_identity(Geometry(points=ring))
    for i in range(len(ring)):
        for r in (ring[i:]+ring[:i], list(reversed(ring[i:]+ring[:i]))):
            assert geometry_identity(Geometry(points=r)) == reference
            assert geometry_identity(Geometry(points=r+[r[0]])) == reference


def test_shape_translation_not_exact():
    a=Geometry(kind="box",points=[(0,0),(1,1)])
    b=Geometry(kind="box",points=[(5,5),(6,6)])
    assert geometry_identity(a) != geometry_identity(b)
    assert geometry_identity(a,True) == geometry_identity(b,True)


def test_same_bounding_box_different_polygon():
    a=Geometry(points=[(0,0),(2,0),(2,2),(0,2)])
    b=Geometry(points=[(0,0),(2,0),(0,2)])
    assert geometry_identity(a)!=geometry_identity(b)


def test_linear_rotation_algorithm_against_bruteforce():
    rng=random.Random(4)
    for n in range(3,35):
        p=[(rng.randint(0,3),rng.randint(0,3)) for _ in range(n)]
        if p[0]==p[-1]:
            p[-1]=(9,9)
        expected=min(r[i:]+r[:i] for r in (p,p[::-1]) for i in range(n))
        assert points(Geometry(points=p))==expected


def test_large_repeated_polygon_is_bounded():
    g=Geometry(points=[(0,0)]*10000)
    assert len(points(g))==9999
