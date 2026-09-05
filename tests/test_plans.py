from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib

from fastapi.testclient import TestClient
import pytest
import yaml

from openwaiver.api import create_app
from openwaiver.errors import Conflict, NotFound
from openwaiver.identity import digest
from openwaiver.models import Principal, utcnow
from openwaiver.plans import AmendOperation, ReviewPlan, apply_plan, preview_plan, proposal_template


def head(service):
    with service.store.transaction(write=False) as conn:
        return service.store.head(conn)


def template(service, actors, run, ids=None):
    return proposal_template(service, actors["alice"], run.id, ids or ["v1"],
        "Reviewed narrow exception for synthetic test", ["bob"], valid_revision=run.revision)


def test_preview_is_read_only_and_apply_proposes_without_approval(service, actors, make_run):
    run = make_run()
    plan = template(service, actors, run)
    before = head(service)
    preview = preview_plan(service, actors["alice"], plan)
    assert head(service) == before
    assert preview == preview_plan(service, actors["alice"], ReviewPlan.model_validate_json(plan.model_dump_json()))
    result = apply_plan(service, actors["alice"], plan, preview["preview_digest"])
    assert result["applied"] and result["approvals_granted"] == 0
    with service.store.transaction(write=False) as conn:
        w = service.store.get(conn, "waivers", result["results"][0]["waiver_id"])
        assert w.status == "proposed" and not w.approvals and not w.evidence
        assert service.store.verify(conn)["valid"]
    assert not service.assessment(run.id)["gate_pass"]


def test_changed_plan_digest_rejected_without_writes(service, actors, make_run):
    plan = template(service, actors, make_run())
    preview = preview_plan(service, actors["alice"], plan)
    plan.operations[0].rationale = "Modified after the reviewed preview was made."
    before = head(service)
    with pytest.raises(Conflict):
        apply_plan(service, actors["alice"], plan, preview["preview_digest"])
    assert head(service) == before


def test_workspace_change_invalidates_plan(service, actors, make_run):
    plan = template(service, actors, make_run())
    preview = preview_plan(service, actors["alice"], plan)
    make_run(revision="r2")
    with pytest.raises(Conflict):
        apply_plan(service, actors["alice"], plan, preview["preview_digest"])


def test_atomic_two_operation_failure_preserves_approved_waiver(service, actors, make_run, make_waiver):
    w = make_waiver(make_run())
    operation = AmendOperation(waiver_id=w.id, version=w.version,
        expected_content_digest=digest(w), changes={"tags": ["review-again"]})
    plan = ReviewPlan(project="chip", created_at=utcnow(), expected_audit_head=head(service),
        note="Atomic editing proof for two waiver changes", operations=[operation,
            AmendOperation(waiver_id="missing", version=1, expected_content_digest="a" * 64, changes={"tags": []})])
    before = head(service)
    with pytest.raises(NotFound):
        apply_plan(service, actors["alice"], plan, "a" * 64)
    assert head(service) == before
    with service.store.transaction(write=False) as conn:
        assert service.store.get(conn, "waivers", w.id) == w


def test_amending_approved_waiver_resets_approvals(service, actors, make_run, make_waiver):
    w = make_waiver(make_run())
    plan = ReviewPlan(project="chip", created_at=utcnow(), expected_audit_head=head(service),
        note="Reconsider engineering rationale using reviewed Git edits", operations=[
        AmendOperation(waiver_id=w.id, version=w.version, expected_content_digest=digest(w),
                       changes={"rationale": "Changed rationale requires fresh evidence review."})])
    preview = preview_plan(service, actors["alice"], plan)
    assert preview["changes"][0]["approvals_removed"] == 1
    applied = apply_plan(service, actors["alice"], plan, preview["preview_digest"])
    assert applied["results"][0]["status"] == "proposed"
    with service.store.transaction(write=False) as conn:
        assert not service.store.get(conn, "waivers", w.id).approvals


@pytest.mark.parametrize("change", [{"status": "approved"}, {"approvals": []}, {"target": {}}, {"evidence": []}, {}])
def test_plan_cannot_import_approval_or_change_target(service, actors, make_run, make_waiver, change):
    w = make_waiver(make_run())
    plan = ReviewPlan(project="chip", created_at=utcnow(), expected_audit_head=head(service),
        note="Untrusted Git edits cannot create approvals", operations=[
        AmendOperation(waiver_id=w.id, version=w.version, expected_content_digest=digest(w), changes=change)])
    with pytest.raises(ValueError):
        preview_plan(service, actors["alice"], plan)


def test_only_one_concurrent_plan_can_commit(service, actors, make_run):
    plan = template(service, actors, make_run())
    preview = preview_plan(service, actors["alice"], plan)
    def attempt(_):
        try:
            apply_plan(service, actors["alice"], plan, preview["preview_digest"])
            return "applied"
        except Conflict:
            return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, range(2))) == ["applied", "conflict"]


def test_duplicate_target_and_future_date_rejected(service, actors, make_run):
    run = make_run()
    with pytest.raises(ValueError):
        template(service, actors, run, ["v1", "v1"])
    plan = template(service, actors, run)
    plan.created_at = utcnow() + timedelta(days=1)
    with pytest.raises(ValueError):
        preview_plan(service, actors["alice"], plan)


def test_api_plan_end_to_end_and_project_denial(service, actors, make_run):
    plan = template(service, actors, make_run())
    token = {"name": "alice", "role": "contributor", "projects": ["chip"], "sha256": hashlib.sha256(b"test-token").hexdigest()}
    client = TestClient(create_app(service.store.path, [token]))
    auth = {"Authorization": "Bearer test-token"}
    text = yaml.safe_dump(plan.model_dump(mode="json"))
    response = client.post("/api/review-plans/preview", headers=auth, json={"yaml": text})
    assert response.status_code == 200, response.text
    response = client.post("/api/review-plans/apply", headers=auth,
        json={"yaml": text, "expected_digest": response.json()["preview_digest"]})
    assert response.status_code == 200 and response.json()["approvals_granted"] == 0
    scoped = Principal(name="alice", role="admin", projects=["other"])
    with pytest.raises(NotFound):
        preview_plan(service, scoped, plan)
