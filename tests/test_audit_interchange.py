import io
import json
import zipfile

import pytest
import yaml

from openwaiver.engine import compare_snapshots
from openwaiver.errors import Conflict, IntegrityError, OpenWaiverError
from openwaiver.exporters import export_report
from openwaiver.interchange import bundle, git_export, import_yaml_proposal, load_yaml, verify_bundle


def test_audit_detects_state_tampering(service,make_run):
    r=make_run()
    with service.store.transaction() as c:
        value=json.loads(c.execute("SELECT data FROM runs WHERE id=?",(r.id,)).fetchone()[0]);value["revision"]="tampered"
        c.execute("UPDATE runs SET data=? WHERE id=?",(json.dumps(value),r.id))
    with pytest.raises(IntegrityError):service.assessment(r.id)


def test_audit_detects_deleted_event(service,make_run):
    make_run()
    with service.store.transaction() as c:c.execute("DELETE FROM audit WHERE seq=1")
    with service.store.transaction(write=False) as c:
        with pytest.raises(IntegrityError):service.store.verify(c)


def test_audit_external_checkpoint(service,make_run):
    make_run()
    with service.store.transaction(write=False) as c:
        head=service.store.head(c)
        assert service.store.verify(c,head)["externally_anchored"]
        with pytest.raises(IntegrityError):service.store.verify(c,"0"*64)


def test_evidence_bytes_verified(service,make_run,make_waiver):
    r=make_run();make_waiver(r)
    with service.store.transaction() as c:c.execute("UPDATE evidence SET data=?",(b"modified",))
    with pytest.raises(IntegrityError):service.assessment(r.id)


def test_snapshots_do_not_recompute_history(service,actors,make_run,make_waiver):
    r=make_run();w=make_waiver(r)
    old=service.freeze(actors["bob"],r.id,"A",require_clean=True)
    service.revoke(actors["alice"],w.id,w.version,"Design assumption no longer valid")
    new=service.freeze(actors["bob"],r.id,"B")
    diff=compare_snapshots(old,new)
    assert diff["before_gate"] and not diff["after_gate"]
    assert diff["waivers_changed"]==[w.id]
    with service.store.transaction(write=False) as c:
        assert service.store.get(c,"snapshots",old.id).assessment["gate_pass"]


def test_freeze_require_clean(service,actors,make_run):
    r=make_run()
    with pytest.raises(Conflict):service.freeze(actors["bob"],r.id,"Not clean",require_clean=True)


def test_bundle_hmac_and_tamper(service,actors,make_run,make_waiver):
    r=make_run();make_waiver(r);snap=service.freeze(actors["bob"],r.id,"A")
    data=bundle(service,snap.id,b"external-secret-key-32-bytes-minimum")
    verified=verify_bundle(data,b"external-secret-key-32-bytes-minimum")
    assert verified["hmac_verified"]
    with pytest.raises(IntegrityError):verify_bundle(data,b"w"*32)
    with pytest.raises(IntegrityError):verify_bundle(data,expected_manifest="0"*64)
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        entries={n:source.read(n) for n in source.namelist()}
    entries["snapshot.json"]=b"{}"
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w") as z:
        for name,value in entries.items():z.writestr(name,value)
    with pytest.raises(IntegrityError):verify_bundle(out.getvalue())


def test_unsigned_bundle_does_not_claim_authenticity(service,actors,make_run):
    snap=service.freeze(actors["bob"],make_run().id,"A")
    result=verify_bundle(bundle(service,snap.id))
    assert result["valid"] and not result["externally_anchored"] and not result["hmac_verified"]


def test_zip_path_traversal_rejected():
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w") as z:z.writestr("../outside",b"x")
    with pytest.raises(IntegrityError):verify_bundle(out.getvalue())


def test_git_export_deterministic(service,make_run,make_waiver,tmp_path):
    make_waiver(make_run())
    a,b=tmp_path/"one",tmp_path/"two"
    git_export(service,a);git_export(service,b)
    assert {p.relative_to(a):p.read_bytes() for p in a.rglob("*") if p.is_file()}=={p.relative_to(b):p.read_bytes() for p in b.rglob("*") if p.is_file()}
    with pytest.raises(OpenWaiverError):git_export(service,a)


@pytest.mark.parametrize("source", ["a: 1\na: 2", "a: &x [1,2]\nb: *x", "a: !!python/object/apply:os.system ['touch /tmp/no']"])
def test_unsafe_yaml(source):
    with pytest.raises((OpenWaiverError,yaml.YAMLError)):load_yaml(source)


def test_yaml_approval_is_not_trusted(service,actors,make_run,make_waiver):
    r=make_run();w=make_waiver(r)
    text=yaml.safe_dump(w.model_dump(mode="json"))
    service.revoke(actors["alice"],w.id,w.version,"Import as a new proposal")
    new=import_yaml_proposal(service,actors["alice"],text)
    assert new.status=="proposed" and not new.approvals and not new.evidence
    assert not service.assessment(r.id)["gate_pass"]


def test_native_export_requires_lossy_ack(service,make_run,make_waiver):
    r=make_run();make_waiver(r)
    a=service.assessment(r.id)
    with pytest.raises(OpenWaiverError):export_report(a,"verilator")
    native=export_report(a,"verilator",acknowledge_lossy=True)
    assert 'lint_off -rule WIDTH -file "rtl/top.sv" -lines 21' in native
    assert "GENERATED DERIVATIVE" in native


def test_native_export_injection_rejected(service,make_run,make_waiver,record):
    r=make_run([{**record,"path":"rtl/*.sv"}]);make_waiver(r)
    with pytest.raises(OpenWaiverError):export_report(service.assessment(r.id),"verilator",acknowledge_lossy=True)


def test_sarif_only_actual_suppressions(service,make_run,make_waiver,record):
    make_waiver(make_run())
    r=make_run([record,{**record,"id":"v2","line":50}])
    doc=json.loads(export_report(service.assessment(r.id),"sarif"))
    items=doc["runs"][0]["results"]
    assert "suppressions" in items[0] and "suppressions" not in items[1]


def test_html_and_junit_escape_payload(service,make_run,record):
    r=make_run([{**record,"message":'<script>alert("x")</script>',"rule":"<svg/onload=evil>"}])
    a=service.assessment(r.id)
    html=export_report(a,"html")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "<svg/onload" not in export_report(a,"junit")


@pytest.mark.parametrize('key', [b'', b'weak', b'x'*31])
def test_weak_hmac_key_never_claims_authentication(service, actors, make_run, key):
    snap = service.freeze(actors['bob'], make_run().id, 'A')
    with pytest.raises(IntegrityError):
        bundle(service, snap.id, key)
    with pytest.raises(IntegrityError):
        verify_bundle(bundle(service, snap.id), key)


def test_frozen_bundle_stable_after_later_waiver_change(service, actors, make_run, make_waiver):
    run = make_run()
    w = make_waiver(run)
    snap = service.freeze(actors['bob'], run.id, 'A')
    original = bundle(service, snap.id)
    service.amend(actors['alice'], w.id, w.version, {'rationale': 'Later engineering review invalidates this old justification.'})
    assert bundle(service, snap.id) == original
    assert not service.assessment(run.id)['gate_pass']


def test_malformed_zip_is_friendly_error():
    with pytest.raises(IntegrityError):
        verify_bundle(b'not a ZIP')


@pytest.mark.parametrize('source', ['a: [', '? [a,b]\n: value', '['*41+']'*41])
def test_malformed_or_deep_yaml_is_friendly_error(source):
    with pytest.raises(OpenWaiverError):
        load_yaml(source)
