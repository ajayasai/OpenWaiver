from datetime import timedelta

import pytest
from pydantic import ValidationError

from openwaiver.errors import Conflict, Forbidden, OpenWaiverError
from openwaiver.models import Policy, Principal, utcnow


def test_complete_lifecycle(service, actors, make_run, make_waiver):
    r=make_run();w=make_waiver(r)
    assert w.status=="approved" and service.assessment(r.id)["gate_pass"]
    w=service.revoke(actors["bob"],w.id,w.version,"Assumption invalidated")
    assert w.status=="revoked" and not service.assessment(r.id)["gate_pass"]


def test_evidence_required(service, actors, make_run, make_waiver):
    r=make_run();w=make_waiver(r,approve=False,submit=False,evidence=False)
    with pytest.raises(OpenWaiverError,match="evidence"):
        service.submit(actors["alice"],w.id,w.version)


def test_no_self_approval(service, actors, make_run):
    r=make_run()
    with pytest.raises(ValidationError):
        service.propose(actors["alice"],run_id=r.id,violation_id="v1",rationale="Long engineering rationale",
                        owner="alice",reviewers=["alice"],valid_revision=r.revision)


def test_independent_admin_no_override(service, actors, make_run, make_waiver):
    w=make_waiver(make_run(),approve=False)
    with pytest.raises(Forbidden):service.review(actors["root"],w.id,w.version,"approve","Admin should not bypass independence")


def test_contributor_cannot_review(service, actors, make_run, make_waiver):
    w=make_waiver(make_run(),approve=False)
    bob=Principal(name="bob",role="contributor")
    with pytest.raises(Forbidden):service.review(bob,w.id,w.version,"approve","Still no reviewer role")


def test_risk_based_dual_review(service, actors, make_run, make_waiver, record):
    run=make_run([{**record,"category":"cdc"}])
    w=make_waiver(run,approve=False,reviewers=["bob","carol"])
    w=service.review(actors["bob"],w.id,w.version,"approve","Independent first approval")
    assert w.status=="submitted" and not service.assessment(run.id)["gate_pass"]
    w=service.review(actors["carol"],w.id,w.version,"approve","Independent second approval")
    assert w.status=="approved" and service.assessment(run.id)["gate_pass"]


def test_reviewer_cannot_vote_twice(service, actors, make_run, make_waiver, record):
    w=make_waiver(make_run([{**record,"category":"cdc"}]),approve=False,reviewers=["bob","carol"])
    w=service.review(actors["bob"],w.id,w.version,"approve","First vote accepted")
    with pytest.raises(Conflict):service.review(actors["bob"],w.id,w.version,"approve","Second vote rejected")


def test_edit_resets_approval(service, actors, make_run, make_waiver):
    r=make_run();w=make_waiver(r)
    w=service.amend(actors["alice"],w.id,w.version,{"rationale":"Amended engineering assumptions requiring another review"})
    assert w.status=="proposed" and not w.approvals and not service.assessment(r.id)["gate_pass"]
    with service.store.transaction(write=False) as c:
        history=[e for e in service.store.events(c) if e["entity"]=="waivers"]
    assert history[-2]["record"]["approvals"] and history[-1]["action"].startswith("amend")


def test_stale_write_conflicts(service, actors, make_run, make_waiver):
    w=make_waiver(make_run(),approve=False,submit=False)
    version=w.version
    service.amend(actors["alice"],w.id,version,{"tags":["one"]})
    with pytest.raises(Conflict):service.amend(actors["alice"],w.id,version,{"tags":["two"]})


def test_rebind_requires_reapproval(service, actors, make_run, make_waiver, record):
    a=make_run();w=make_waiver(a)
    b=make_run([{**record,"line":25}],revision="rev-b")
    assert service.assessment(b.id)["counts"]=={"needs_review":1}
    w=service.rebind(actors["alice"],w.id,w.version,b.id,"v1")
    assert w.status=="proposed" and not w.approvals
    assert not service.assessment(b.id)["gate_pass"]


def test_revision_bound_no_order_inference(service, actors, make_run, make_waiver, record):
    a=make_run();make_waiver(a,expires_on=None,valid_revision="rev-a")
    b=make_run(revision="rev-a-child")
    assert service.assessment(a.id)["gate_pass"]
    assert service.assessment(b.id)["counts"]=={"stale":1}


def test_no_unbounded_waiver(make_run, make_waiver):
    with pytest.raises(ValidationError):make_waiver(make_run(),expires_on=None,approve=False,submit=False)


def test_past_expiry_rejected(make_run,make_waiver):
    with pytest.raises(OpenWaiverError):make_waiver(make_run(),expires_on=utcnow().date()-timedelta(days=1))


def test_policy_horizon(make_run,make_waiver):
    with pytest.raises(OpenWaiverError):make_waiver(make_run(),expires_on=utcnow().date()+timedelta(days=91))


def test_policy_changes_reassess(service,actors,make_run,make_waiver):
    r=make_run();make_waiver(r)
    service.set_policy(actors["root"],Policy(forbidden_rules=["WIDTH"]))
    assert service.assessment(r.id)["counts"]=={"stale":1}


def test_duplicate_target_rejected(make_run,make_waiver):
    r=make_run();make_waiver(r)
    with pytest.raises(Conflict):make_waiver(r)


def test_aggregate_marker_not_silently_waived(make_run,make_waiver,record):
    r=make_run([{**record,"multiplicity":4}])
    with pytest.raises(OpenWaiverError,match="aggregate"):
        make_waiver(r)


def test_rejection_can_be_amended_and_resubmitted(service,actors,make_run,make_waiver):
    w=make_waiver(make_run(),approve=False)
    w=service.review(actors["bob"],w.id,w.version,"reject","Insufficient engineering justification")
    assert w.status=="rejected"
    w=service.amend(actors["alice"],w.id,w.version,{"rationale":"Detailed corrected engineering justification and constraints"})
    w=service.submit(actors["alice"],w.id,w.version)
    assert w.status=="submitted" and not w.approvals


@pytest.mark.parametrize("filename,data", [("../report.txt",b"x"),(".secret.txt",b"x"),
    ("payload.svg",b"<svg>"),("false.png",b"not-png"),("report.pdf",b"not-pdf")])
def test_attachment_validation(service,actors,make_run,make_waiver,filename,data):
    w=make_waiver(make_run(),approve=False,submit=False,evidence=False)
    with pytest.raises(OpenWaiverError):service.attach(actors["alice"],w.id,w.version,filename,data)


def test_evidence_cannot_change_after_approval(service,actors,make_run,make_waiver):
    w=make_waiver(make_run())
    with pytest.raises(Conflict):service.attach(actors["alice"],w.id,w.version,"new.txt",b"new proof")


def test_terminal_revocation(service,actors,make_run,make_waiver):
    r=make_run();w=make_waiver(r)
    w=service.revoke(actors["alice"],w.id,w.version,"No longer required")
    with pytest.raises(Conflict):service.rebind(actors["alice"],w.id,w.version,r.id,"v1")
    with pytest.raises(Conflict):service.amend(actors["alice"],w.id,w.version,{"tags":[]})
