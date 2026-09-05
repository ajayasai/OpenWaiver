from datetime import timedelta

import pytest

from openwaiver.engine import assess
from openwaiver.models import Policy, Scope, utcnow


def test_exact_cross_revision_with_context(service,make_run,make_waiver):
    make_waiver(make_run())
    b=make_run(revision="rev-b")
    assert service.assessment(b.id)["gate_pass"]


@pytest.mark.parametrize("change", [{"context_hash":"f"*64},{"context_hash":""}])
def test_context_changed_or_missing_stales(service,make_run,make_waiver,record,change):
    make_waiver(make_run())
    b=make_run([{**record,**change}],revision="rev-b")
    result=service.assessment(b.id)
    assert not result["gate_pass"] and result["counts"]=={"stale":1}


def test_unknown_context_across_revision(service,make_run,make_waiver,record):
    a=make_run([{**record,"context_hash":""}]);make_waiver(a)
    b=make_run([{**record,"context_hash":""}],revision="rev-b")
    assert service.assessment(a.id)["gate_pass"]
    assert service.assessment(b.id)["counts"]=={"stale":1}


@pytest.mark.parametrize("kw", [{"tool_version":"new"},{"rule_deck_digest":"new"},{"configuration_digest":"new"}])
def test_provenance_changes_stale(service,make_run,make_waiver,kw):
    make_waiver(make_run())
    b=make_run(**kw)
    assert service.assessment(b.id)["counts"]=={"stale":1}


@pytest.mark.parametrize("field",["project","stream","tool"])
def test_scope_isolation(service,make_run,make_waiver,field):
    a=make_run();make_waiver(a)
    b=make_run(scope=Scope(**{**a.scope.model_dump(),field:"another"}))
    result=service.assessment(b.id)
    assert result["counts"]=={"open":1} and not result["waivers"]


def test_duplicate_exact_finding_is_ambiguous(service,make_run,make_waiver,record):
    make_waiver(make_run())
    b=make_run([record,{**record,"id":"v2"}])
    assert service.assessment(b.id)["counts"]=={"ambiguous":2}


def test_one_to_many_candidate_is_ambiguous(service,make_run,make_waiver,record):
    make_waiver(make_run())
    b=make_run([{**record,"line":22},{**record,"id":"v2","line":23}])
    assert service.assessment(b.id)["counts"]=={"ambiguous":2}


def test_candidate_cannot_reuse_consumed_target(service,make_run,make_waiver,record):
    make_waiver(make_run())
    b=make_run([record,{**record,"id":"v2","line":22}])
    assert service.assessment(b.id)["counts"]=={"waived":1,"ambiguous":1}


def test_unused_only_complete_coverage(service,make_run,make_waiver):
    make_waiver(make_run())
    full=make_run([])
    partial=make_run([],complete=False)
    other=make_run([],checked_categories=["drc"])
    assert service.assessment(full.id)["waivers"][0]["status"]=="unused"
    assert service.assessment(partial.id)["waivers"][0]["status"]=="not_observed"
    assert service.assessment(other.id)["waivers"][0]["status"]=="not_observed"
    assert service.assessment(full.id)["gate_pass"]
    assert not service.assessment(partial.id)["gate_pass"]


def test_expiration_inclusive(service,make_run,make_waiver):
    r=make_run();w=make_waiver(r)
    assert service.assessment(r.id,today=w.expires_on)["gate_pass"]
    assert service.assessment(r.id,today=w.expires_on+timedelta(days=1))["counts"]=={"expired":1}


@pytest.mark.parametrize("points", [[[1,0],[3,2]],[[0,0],[3,2]]])
def test_moved_and_reshaped_geometry_never_auto_approved(service,make_run,make_waiver,record,points):
    a={**record,"category":"drc","geometries":[{"kind":"box","points":[[0,0],[2,2]],"layer":"M2"}]}
    make_waiver(make_run([a]))
    b={**a,"geometries":[{"kind":"box","points":points,"layer":"M2"}]}
    result=service.assessment(make_run([b]).id)
    assert result["counts"]=={"needs_review":1}
    assert not result["gate_pass"]


def test_units_not_guessed(service,make_run,make_waiver,record):
    a={**record,"path":"","line":None,"column":None,"category":"drc","geometries":[{"kind":"box","points":[[0,0],[2,2]],"unit":"um"}]}
    make_waiver(make_run([a]))
    b={**a,"geometries":[{"kind":"box","points":[[0,0],[2,2]],"unit":"nm"}]}
    assert not service.assessment(make_run([b]).id)["gate_pass"]


def test_tampered_approval_digest_fails_closed(make_run,make_waiver):
    r=make_run();w=make_waiver(r)
    w=w.model_copy(update={"rationale":"Altered accepted rationale without a new review"})
    result=assess(r,[w],Policy(),utcnow().date())
    assert result["counts"]=={"stale":1}


def test_candidate_budget_exhaustion_not_unused(make_run,make_waiver,record):
    a=make_run();w=make_waiver(a)
    clone=w.model_copy(update={"id":"second"})
    b=make_run([{**record,"line":22}])
    result=assess(b,[w,clone],Policy(candidate_limit=1),utcnow().date())
    assert result["counts"]=={"ambiguous":1}
    assert all(w["status"]=="not_observed" for w in result["waivers"])
