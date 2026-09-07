from datetime import timedelta
import copy
import hashlib
import io
import json
import stat
import zipfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openwaiver.assurance import ReleaseContract, RiskBudget, capture_inventory, evaluate_contract
from openwaiver.attestation import Attestation, key_id, sign_claim
from openwaiver.capsule import seal_capsule, verify_capsule
from openwaiver.errors import IntegrityError, OpenWaiverError
from openwaiver.execution import (ExecutionClaim, ExecutionReceipt, ReleaseTrust, public_key,
                                 read_trust, sign_execution, verify_execution)
from openwaiver.identity import canonical, digest
from openwaiver.models import Policy, Principal, Scope, utcnow


def pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@pytest.fixture
def release_case(make_run):
    run = make_run([], tool_version="test-1", rule_deck_digest="a" * 64, configuration_digest="b" * 64)
    now = run.created_at + timedelta(seconds=1)
    producer, publisher = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    bounds = dict(not_before=now - timedelta(days=10), not_after=now + timedelta(days=10))
    trust = ReleaseTrust(producers=[dict(public_key_pem=pem(producer), scopes=[run.scope], **bounds)],
                         publishers=[dict(public_key_pem=pem(publisher), projects=[run.scope.project], **bounds)])
    contract = ReleaseContract(manifest=dict(project=run.scope.project, revision=run.revision,
        checks=[dict(stream=run.scope.stream, tool=run.scope.tool, categories=["lint"], run_id=run.id,
            tool_version=run.tool_version, rule_deck_digest=run.rule_deck_digest,
            configuration_digest=run.configuration_digest)]), policy_sha256=digest(Policy()), design_sha256="d" * 64)
    trust.approved_contracts = [digest(contract)]

    def receipt(for_run=run, **changes):
        values = dict(run_id=for_run.id, run_sha256=digest(for_run), design_sha256=contract.design_sha256,
                      invocation_sha256="e" * 64, stdout_sha256="f" * 64, stderr_sha256="0" * 64,
                      started_at=for_run.created_at - timedelta(seconds=3),
                      finished_at=for_run.created_at - timedelta(seconds=1), exit_code=0, complete=True, unfiltered=True)
        values.update(changes)
        return sign_execution(ExecutionClaim(**values), producer, now=now)

    return dict(run=run, now=now, producer=producer, publisher=publisher, trust=trust,
                contract=contract, receipt=receipt)


def evaluate(case, **changes):
    values = dict(contract=case["contract"], runs=[case["run"]], waivers=[], policy=Policy(),
                  receipts=[case["receipt"]()], trust=case["trust"], now=case["now"])
    values.update(changes)
    return evaluate_contract(**values)


def test_recent_import_without_execution_receipt_is_blocked(release_case):
    assert evaluate(release_case)["gate_pass"]
    blocked = evaluate(release_case, receipts=[])
    assert not blocked["gate_pass"] and blocked["blockers"][0]["code"] == "execution_receipt"


def test_old_execution_cannot_be_refreshed_by_new_import(release_case):
    c = release_case
    r = c["receipt"](started_at=c["now"]-timedelta(days=3,seconds=2), finished_at=c["now"]-timedelta(days=3))
    result = evaluate(c, receipts=[r])
    assert not result["gate_pass"] and "freshness" in str(result)


@pytest.mark.parametrize("change", [{"exit_code": 1}, {"complete": False}, {"unfiltered": False},
                                    {"run_sha256": "9"*64}, {"design_sha256": "9"*64}])
def test_bad_but_signed_producer_claim_blocks(release_case, change):
    assert not evaluate(release_case, receipts=[release_case["receipt"](**change)])["gate_pass"]


@pytest.mark.parametrize("field", ["run_sha256", "design_sha256", "invocation_sha256", "stdout_sha256", "stderr_sha256"])
def test_post_signature_mutation_detected(release_case, field):
    r = release_case["receipt"]()
    setattr(r.claim, field, "8"*64)
    result = evaluate(release_case, receipts=[r])
    assert not result["gate_pass"] and "bytes changed" in str(result)


def test_signature_cannot_use_unauthorized_key(release_case):
    r = release_case["receipt"]()
    r.attestation = sign_claim(r.attestation.claim, Ed25519PrivateKey.generate())
    assert not evaluate(release_case, receipts=[r])["gate_pass"]


@pytest.mark.parametrize("change", [{"revoked": True}, {"scopes": [Scope(project="other",stream="nightly",tool="verilator")]}])
def test_producer_scope_and_revocation(release_case, change):
    trust = release_case["trust"].model_dump()
    trust["producers"][0].update(change)
    assert not evaluate(release_case, trust=ReleaseTrust(**trust))["gate_pass"]


def test_key_validity_checked_at_issuance_and_assessment(release_case):
    c = release_case
    trust = c["trust"].model_dump()
    trust["producers"][0]["not_after"] = c["now"] + timedelta(seconds=1)
    assert not evaluate(c, trust=ReleaseTrust(**trust), now=c["now"]+timedelta(seconds=2))["gate_pass"]
    trust["producers"][0]["not_before"] = c["now"] + timedelta(seconds=0.5)
    assert not evaluate(c, trust=ReleaseTrust(**trust))["gate_pass"]


def test_separate_producer_and_publisher_keys_required(release_case):
    trust = release_case["trust"].model_dump()
    trust["publishers"][0]["public_key_pem"] = pem(release_case["producer"])
    with pytest.raises(ValueError, match="separate"):
        ReleaseTrust(**trust)


@pytest.mark.parametrize("change", [{"tool_version":"wrong"}, {"rule_deck_digest":"c"*64},
                                    {"configuration_digest":"c"*64}, {"categories":["lint","drc"]}])
def test_every_check_is_pinned(release_case, change):
    contract = release_case["contract"].model_dump()
    contract["manifest"]["checks"][0].update(change)
    assert not evaluate(release_case, contract=ReleaseContract(**contract))["gate_pass"]


def test_policy_cannot_be_weakened_without_new_contract(release_case):
    result = evaluate(release_case, policy=Policy(require_evidence=False, gate_severities=[]))
    assert not result["gate_pass"] and "policy_mismatch" in str(result)


@pytest.mark.parametrize("change", [{"run_id": None}, {"tool_version": ""}, {"rule_deck_digest":""},
                                    {"configuration_digest":"not-a-hash"}, {"tool":" verilator"}])
def test_contract_rejects_unpinned_checks(release_case, change):
    raw = release_case["contract"].model_dump()
    raw["manifest"]["checks"][0].update(change)
    with pytest.raises(ValueError):
        ReleaseContract(**raw)


@pytest.mark.parametrize("budget", [{"max_waived_findings":-1}, {"max_waived_findings":True},
                                    {"max_by_category":{"lint":True}}, {"max_by_category":{"lint":-1}},
                                    {"minimum_remaining_days":-1}, {"max_by_category":{"lint":1.1}}])
def test_budget_validation(budget):
    with pytest.raises(ValueError):
        RiskBudget(**budget)


def test_duplicate_or_foreign_receipts_and_inventory_rejected(release_case):
    c = release_case
    with pytest.raises(IntegrityError, match="duplicate"):
        evaluate(c, receipts=[c["receipt"](), c["receipt"]()])
    r = c["receipt"]()
    r.claim.run_id = "not-selected"
    with pytest.raises(IntegrityError, match="unselected"):
        evaluate(c, receipts=[r])
    with pytest.raises(IntegrityError, match="duplicate"):
        evaluate(c, runs=[c["run"], c["run"]])


def test_naive_time_and_expired_receipt(release_case):
    c = release_case
    with pytest.raises(ValueError):
        evaluate(c, now=c["now"].replace(tzinfo=None))
    assert not evaluate(c, now=c["now"]+timedelta(days=2))["gate_pass"]


def test_inconsistent_execution_import_order(release_case):
    c = release_case
    r = c["receipt"](finished_at=c["run"].created_at+timedelta(seconds=.5))
    result = evaluate(c, receipts=[r])
    assert not result["gate_pass"] and "timestamps" in str(result)


def test_missing_run_wrong_revision_incomplete_and_future(release_case):
    c=release_case
    assert not evaluate(c, runs=[])["gate_pass"]
    for changes in [{"revision":"wrong"},{"complete":False},{"created_at":c["now"]+timedelta(days=1)}]:
        r=c["run"].model_copy(update=changes)
        assert not evaluate(c, runs=[r])["gate_pass"]


def test_two_checks_cannot_be_replaced_by_one_clean_run(release_case, make_run):
    c=release_case
    r=make_run([],scope=Scope(project="chip",stream="drc",tool="klayout"),checked_categories=["drc"],
               tool_version="test-1",rule_deck_digest="a"*64,configuration_digest="b"*64)
    contract=c["contract"].model_dump()
    check=copy.deepcopy(contract["manifest"]["checks"][0])
    check.update(stream="drc",tool="klayout",categories=["drc"],run_id=r.id)
    contract["manifest"]["checks"].append(check)
    contract=ReleaseContract(**contract)
    assert not evaluate(c, contract=contract)["gate_pass"]
    assert not evaluate(c, contract=contract,runs=[c["run"],r])["gate_pass"]
    trust=c["trust"].model_dump()
    trust["producers"][0]["scopes"].append(r.scope.model_dump())
    trust["approved_contracts"] = [digest(contract)]
    receipts=[c["receipt"](),c["receipt"](r)]
    assert evaluate(c,contract=contract,runs=[c["run"],r],receipts=receipts,trust=ReleaseTrust(**trust))["gate_pass"]


@pytest.fixture
def waived_case(release_case, service, record, actors):
    c=release_case
    run=service.import_run(actors["alice"],content=json.dumps(dict(schema_version=1,violations=[record])),format="json",
        scope=c["run"].scope, revision=c["run"].revision, complete=True, checked_categories=["lint"],
        tool_version="test-1",rule_deck_digest="a"*64,configuration_digest="b"*64)
    c["run"] = run
    c["now"] = run.created_at + timedelta(seconds=1)
    c["contract"].manifest.checks[0].run_id = run.id
    c["trust"].approved_contracts = [digest(c["contract"])]
    return c


def test_risk_budgets_and_expiration_protect_release(waived_case, make_waiver):
    c=waived_case
    w=make_waiver(c["run"])
    values=dict(runs=[c["run"]],receipts=[c["receipt"](c["run"])],waivers=[w])
    result=evaluate(c,**values)
    assert not result["gate_pass"] and result["risk"]["waived_findings"]==1
    c["contract"].budget.max_waived_findings=1
    c["trust"].approved_contracts = [digest(c["contract"])]
    assert evaluate(c,**values)["gate_pass"]
    c["contract"].budget.max_by_category={"lint":0}
    assert "category_budget" in str(evaluate(c,**values))
    c["contract"].budget.max_by_category={}
    c["contract"].budget.minimum_remaining_days=31
    assert "expiry_horizon" in str(evaluate(c,**values))


def test_capture_inventory_does_not_export_other_projects(release_case, service, make_run, actors):
    c=release_case
    foreign=make_run([],scope=Scope(project="foreign",stream="secret",tool="private"))
    actor=Principal(name="a",role="viewer",projects=["chip"])
    inv=capture_inventory(service,c["contract"],actor)
    assert [r.id for r in inv["runs"]]==[c["run"].id]
    c["contract"].manifest.checks[0].run_id=foreign.id
    assert capture_inventory(service,c["contract"],actor)["runs"]==[]
    c["contract"].manifest.project="foreign"
    with pytest.raises(OpenWaiverError):
        capture_inventory(service,c["contract"],actor)


def test_signed_capsule_replays_without_database(release_case, service, tmp_path):
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    service.store.path.unlink()
    result=verify_capsule(data,c["contract"],c["trust"],c["now"])
    assert result["valid"] and result["historical_gate_pass"] and result["frozen_state_gate_pass_now"]
    assert result["publisher_authenticated"] and result["historical_assessment_replayed"]


def test_old_capsule_cannot_be_reported_as_currently_usable(release_case, service):
    c=release_case
    c["contract"].max_execution_age_hours=1
    c["trust"].approved_contracts = [digest(c["contract"])]
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    result=verify_capsule(data,c["contract"],c["trust"],c["now"]+timedelta(hours=2))
    assert result["historical_gate_pass"] and not result["frozen_state_gate_pass_now"] and not result["frozen_state_gate_pass_now"]


def test_capsule_with_evidence_and_blocked_diagnostics(waived_case, make_waiver, service):
    c=waived_case
    make_waiver(c["run"])
    receipts=[c["receipt"](c["run"])]
    with pytest.raises(OpenWaiverError,match="blocked"):
        seal_capsule(service,c["contract"],receipts,c["trust"],c["publisher"],now=c["now"])
    data=seal_capsule(service,c["contract"],receipts,c["trust"],c["publisher"],now=c["now"],allow_blocked=True)
    result=verify_capsule(data,c["contract"],c["trust"],c["now"])
    assert result["valid"] and not result["frozen_state_gate_pass_now"] and result["evidence_files"]==1


def rewrite(data, edits, resign=None):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files={n:archive.read(n) for n in archive.namelist()}
    edits(files)
    if resign:
        manifest=canonical({"schema_version":1,"files":{n:hashlib.sha256(v).hexdigest()
            for n,v in files.items() if n not in ("manifest.json","attestation.json")}}).encode()
        files["manifest.json"]=manifest
        seal=Attestation.model_validate_json(files["attestation.json"])
        seal.claim.sha256=hashlib.sha256(manifest).hexdigest()
        files["attestation.json"]=canonical(sign_claim(seal.claim,resign)).encode()
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w") as archive:
        for n,v in files.items(): archive.writestr(n,v)
    return output.getvalue()


@pytest.mark.parametrize("attack",["data","manifest","signature","unexpected","traversal","missing"])
def test_capsule_tampering_rejected(release_case,service,attack):
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    def edit(files):
        if attack=="data": files["release.json"]+=b" "
        elif attack=="manifest": files["manifest.json"]+=b" "
        elif attack=="signature": files["attestation.json"]=b"{}"
        elif attack=="unexpected": files["public-key.pem"]=pem(c["publisher"]).encode()
        elif attack=="traversal": files["../escape"]=b"x"
        else: del files["release.json"]
    with pytest.raises(IntegrityError): verify_capsule(rewrite(data,edit),c["contract"],c["trust"],c["now"])


@pytest.mark.parametrize("attack",["decision","engine","time","receipt","policy","extra-evidence"])
def test_even_publisher_signed_bad_semantics_are_rejected(release_case,service,attack):
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    def edit(files):
        doc=json.loads(files["release.json"])
        if attack=="decision": doc["result"]["gate_pass"]=False
        elif attack=="engine": doc["engine_version"]="900.0"
        elif attack=="time": doc["assessed_at"]=(c["now"]-timedelta(seconds=1)).isoformat()
        elif attack=="receipt": doc["receipts"]=[]
        elif attack=="policy": doc["policy"]["require_evidence"]=False
        else: files["evidence/"+"1"*64]=b"extra"
        files["release.json"]=canonical(doc).encode()
    data=rewrite(data,edit,resign=c["publisher"])
    with pytest.raises(IntegrityError): verify_capsule(data,c["contract"],c["trust"],c["now"])


def test_external_contract_prevents_weaker_embedded_requirements(release_case,service):
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    c["contract"].budget.max_waived_findings=100
    with pytest.raises(IntegrityError): verify_capsule(data,c["contract"],c["trust"],c["now"])


def test_publication_permission_and_revocation(release_case,service):
    c=release_case
    with pytest.raises(IntegrityError):
        seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["producer"],now=c["now"])
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    c["trust"].publishers[0].revoked=True
    with pytest.raises(IntegrityError): verify_capsule(data,c["contract"],c["trust"],c["now"])


def test_duplicate_zip_members_are_rejected(release_case,service):
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    out=io.BytesIO(data)
    with zipfile.ZipFile(out,"a") as archive:
        with pytest.warns(UserWarning): archive.writestr("release.json",b"{}")
    with pytest.raises(IntegrityError,match="duplicate"):
        verify_capsule(out.getvalue(),c["contract"],c["trust"],c["now"])


def test_corrupt_and_symlink_archives_rejected(release_case,service):
    c=release_case
    with pytest.raises(IntegrityError): verify_capsule(b"not zip",c["contract"],c["trust"],c["now"])
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    out=io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as archive, zipfile.ZipFile(out,"w") as dest:
        for entry in archive.infolist():
            entry.external_attr=(stat.S_IFLNK|0o777)<<16
            dest.writestr(entry,archive.read(entry))
    with pytest.raises(IntegrityError): verify_capsule(out.getvalue(),c["contract"],c["trust"],c["now"])


def test_trust_policy_validation_and_file_bounds(release_case,tmp_path):
    c=release_case
    path=tmp_path/"trust.json"
    path.write_text(canonical(c["trust"]))
    assert digest(read_trust(path))==digest(c["trust"])
    link=tmp_path/"link.json"; link.symlink_to(path)
    with pytest.raises(OpenWaiverError): read_trust(link)
    path.write_bytes(b"x"*(1024*1024+1))
    with pytest.raises(OpenWaiverError): read_trust(path)
    with pytest.raises(ValueError): public_key("not pem")


def test_contract_must_be_separately_approved(release_case):
    c=release_case
    c["trust"].approved_contracts=[]
    result=evaluate(c)
    assert not result["gate_pass"] and result["blockers"][0]["code"]=="contract_unapproved"


def test_api_authorization_server_owned_trust_and_live_revocation(release_case,service,tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    from openwaiver.api import create_app
    c=release_case
    c["now"] = utcnow()
    receipt=sign_execution(c["receipt"]().claim,c["producer"],now=c["now"])
    path=tmp_path/"trust.json"; path.write_text(canonical(c["trust"]))
    auth=[dict(name="reader",role="viewer",sha256=hashlib.sha256(b"local-token").hexdigest(),projects=["chip"])]
    client=TestClient(create_app(service.store.path,auth=auth))
    headers={"Authorization":"Bearer local-token"}
    payload={"contract":c["contract"].model_dump(mode="json"),"receipts":[receipt.model_dump(mode="json")]}
    assert client.post("/api/release-assurance/evaluate",json=payload).status_code==401
    assert client.get("/releases").status_code==200
    assert client.get("/static/releases.js").status_code==200
    monkeypatch.delenv("OPENWAIVER_RELEASE_TRUST_FILE",raising=False)
    assert client.post("/api/release-assurance/evaluate",json=payload,headers=headers).status_code==503
    monkeypatch.setenv("OPENWAIVER_RELEASE_TRUST_FILE",str(path))
    result=client.post("/api/release-assurance/evaluate",json=payload,headers=headers)
    assert result.status_code==200, result.text
    assert result.json()["gate_pass"], result.text
    c["trust"].producers[0].revoked=True; path.write_text(canonical(c["trust"]))
    result=client.post("/api/release-assurance/evaluate",json=payload,headers=headers)
    assert not result.json()["gate_pass"]
    assert client.post("/api/release-assurance/evaluate",json={**payload,"trust":{}},headers=headers).status_code==422
    payload["contract"]["manifest"]["project"]="foreign"
    assert client.post("/api/release-assurance/evaluate",json=payload,headers=headers).status_code==404
    path.write_text("broken")
    payload["contract"]["manifest"]["project"]="chip"
    assert client.post("/api/release-assurance/evaluate",json=payload,headers=headers).status_code==503


def test_cli_template_attest_gate_seal_verify_exit_codes(release_case,service,tmp_path,capsys):
    from openwaiver.release_cli import main
    c=release_case
    contract_path=tmp_path/"contract.json"
    args=["template","--db",str(service.store.path),"--project","chip","--revision","rev-a",
          "--run-id",c["run"].id,"--design-sha256",c["contract"].design_sha256,"--output",str(contract_path)]
    assert main(args)==0
    assert not json.loads(capsys.readouterr().out)["authorized"]
    assert digest(ReleaseContract.model_validate_json(contract_path.read_bytes()))==digest(c["contract"])
    assert main(args)==2
    capsys.readouterr()
    producer_path=tmp_path/"producer.pem"; publisher_path=tmp_path/"publisher.pem"
    for path,key in [(producer_path,c["producer"]),(publisher_path,c["publisher"])]:
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        path.chmod(0o600)
    meta=c["receipt"]().claim.model_dump(mode="json"); meta.pop("run_id"); meta.pop("run_sha256")
    meta_path=tmp_path/"meta.json"; meta_path.write_text(canonical(meta))
    receipt_path=tmp_path/"receipt.json"
    assert main(["attest","--db",str(service.store.path),"--run-id",c["run"].id,"--metadata",str(meta_path),
                 "--key",str(producer_path),"--output",str(receipt_path)])==0
    capsys.readouterr()
    trust_path=tmp_path/"trust.json"; trust_path.write_text(canonical(c["trust"]))
    common=["--contract",str(contract_path),"--trust",str(trust_path)]
    source=["--db",str(service.store.path),"--receipt",str(receipt_path)]
    assert main(["gate",*common,*source])==0
    assert json.loads(capsys.readouterr().out)["gate_pass"]
    assert main(["gate",*common,"--db",str(service.store.path)])==1
    assert not json.loads(capsys.readouterr().out)["gate_pass"]
    capsule_path=tmp_path/"release.owrelease"
    assert main(["seal",*common,*source,"--key",str(publisher_path),"--output",str(capsule_path)])==0
    capsys.readouterr()
    assert main(["verify",*common,"--capsule",str(capsule_path)])==0
    assert json.loads(capsys.readouterr().out)["frozen_state_gate_pass_now"]
    trust_path.write_text("{}")
    assert main(["verify",*common,"--capsule",str(capsule_path)])==2


def test_cli_yaml_and_byte_bound(tmp_path):
    from openwaiver.release_cli import read_bytes,read_document
    path=tmp_path/"test.yaml"; path.write_text("project: chip\n")
    assert read_document(path)==dict(project="chip")
    with pytest.raises(ValueError): read_bytes(path,1)


def test_capsule_byte_and_member_limits(release_case,service,monkeypatch):
    import openwaiver.capsule as mod
    c=release_case
    data=seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    with monkeypatch.context() as m:
        m.setattr(mod,"MAX_CAPSULE_BYTES",1)
        with pytest.raises(IntegrityError): verify_capsule(data,c["contract"],c["trust"],c["now"])
        with pytest.raises(OpenWaiverError): seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    with monkeypatch.context() as m:
        m.setattr(mod,"MAX_EXPANDED_BYTES",1)
        with pytest.raises(IntegrityError): verify_capsule(data,c["contract"],c["trust"],c["now"])
        with pytest.raises(OpenWaiverError): seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"])
    with pytest.raises(ValueError): seal_capsule(service,c["contract"],[c["receipt"]()],c["trust"],c["publisher"],now=c["now"],hours=0)


def test_invalid_private_model_copy_revalidated(release_case):
    c=release_case
    c["contract"] = c["contract"].model_copy(update={"max_execution_age_hours":float("inf")})
    with pytest.raises(ValueError): evaluate(c)


@pytest.mark.parametrize("attack",["future","rejection","duplicate","fingerprint"])
def test_impossible_review_history_cannot_authorize_release(waived_case,make_waiver,attack):
    c=waived_case
    w=make_waiver(c["run"])
    c["contract"].budget.max_waived_findings=1
    c["trust"].approved_contracts=[digest(c["contract"])]
    if attack=="future": w.approvals[0].at=c["now"]+timedelta(days=1)
    elif attack=="rejection":
        rejected=w.approvals[0].model_copy(update={"actor":"someone-else","decision":"reject"})
        w.approvals.append(rejected)
    elif attack=="duplicate": w.approvals.append(w.approvals[0])
    else: w.fingerprint="0"*64
    values=dict(runs=[c["run"]],receipts=[c["receipt"](c["run"])],waivers=[w])
    if attack=="fingerprint":
        with pytest.raises(IntegrityError): evaluate(c,**values)
    else: assert not evaluate(c,**values)["gate_pass"]


def test_live_reconciliation_detects_revocation_after_freeze(waived_case,service,make_waiver,actors):
    c=waived_case
    w=make_waiver(c["run"])
    c["contract"].budget.max_waived_findings=1
    c["trust"].approved_contracts=[digest(c["contract"])]
    data=seal_capsule(service,c["contract"],[c["receipt"](c["run"])],c["trust"],c["publisher"],now=c["now"])
    live=verify_capsule(data,c["contract"],c["trust"],c["now"],service=service)
    assert live["live_state_checked"] and live["live_state_matches"] and live["release_usable_now"]
    service.revoke(actors["alice"],w.id,w.version,"Withdraw fixture approval")
    offline=verify_capsule(data,c["contract"],c["trust"],c["now"])
    assert offline["historical_gate_pass"] and offline["frozen_state_gate_pass_now"]
    assert offline["release_usable_now"] is None and not offline["live_state_checked"]
    live=verify_capsule(data,c["contract"],c["trust"],c["now"],service=service)
    assert not live["live_state_matches"] and not live["release_usable_now"] and not live["live_gate_pass"]
