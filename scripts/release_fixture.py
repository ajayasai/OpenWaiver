"""Synthetic-only fixture helpers; generated signing keys never leave process memory."""
from datetime import timedelta
import hashlib
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openwaiver.assurance import ReleaseContract
from openwaiver.execution import ExecutionClaim, ReleaseTrust, sign_execution
from openwaiver.identity import digest
from openwaiver.models import Principal, Scope, utcnow


def assemble(service, runs, executions, design_sha256):
    producer, publisher = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    owner=Principal(name="fixture-engineer",role="contributor")
    reviewer=Principal(name="independent-reviewer",role="reviewer")
    for run in runs:
        for v in run.violations:
            w=service.propose(owner,run_id=run.id,violation_id=v.id,owner=owner.name,reviewers=[reviewer.name],
                rationale="Synthetic integration fixture only; never use this waiver on a real chip.",valid_revision=run.revision)
            w=service.attach(owner,w.id,w.version,"fixture-evidence.txt",b"Synthetic test evidence only.")
            w=service.submit(owner,w.id,w.version)
            service.review(reviewer,w.id,w.version,"approve","Independent synthetic fixture review.")
    now=utcnow()
    checks=[dict(stream=r.scope.stream,tool=r.scope.tool,categories=r.checked_categories,run_id=r.id,
                 tool_version=r.tool_version,rule_deck_digest=r.rule_deck_digest,configuration_digest=r.configuration_digest) for r in runs]
    with service.store.transaction(write=False) as conn:
        contract=ReleaseContract(manifest=dict(project=runs[0].scope.project,revision=runs[0].revision,checks=checks),
            policy_sha256=digest(service.store.policy(conn)),design_sha256=design_sha256,
            budget=dict(max_waived_findings=sum(len(r.violations) for r in runs)))
    def pem(k):
        return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    bounds=dict(not_before=now-timedelta(days=1),not_after=now+timedelta(days=2))
    trust=ReleaseTrust(approved_contracts=[digest(contract)],
        producers=[dict(public_key_pem=pem(producer),scopes=[r.scope for r in runs],**bounds)],
        publishers=[dict(public_key_pem=pem(publisher),projects=[runs[0].scope.project],**bounds)])
    receipts=[]
    for run,execution in zip(runs,executions,strict=True):
        claim=ExecutionClaim(run_id=run.id,run_sha256=digest(run),design_sha256=design_sha256,**execution)
        receipts.append(sign_execution(claim,producer,now=now))
    return contract,trust,receipts,publisher,now


def synthetic_workspace(service):
    runs,executions=[],[]
    for tool,category in [("verilator","lint"),("klayout","drc")]:
        text=json.dumps({"schema_version":1,"violations":[dict(id=f"{category}-1",category=category,
            rule="SYNTHETIC.CHECK",path="fixture/example.txt",line=1,message="Synthetic fixture finding",severity="warning")]})
        started=utcnow()-timedelta(seconds=2); finished=utcnow()-timedelta(seconds=1)
        run=service.import_run(Principal(name="fixture-engineer",role="contributor"),content=text,format="json",
            scope=Scope(project="sample-chip",stream=category,tool=tool),revision="candidate-A",complete=True,
            checked_categories=[category],tool_version="synthetic-1",rule_deck_digest=digest("synthetic-check"),
            configuration_digest=digest("synthetic-configuration"))
        runs.append(run)
        executions.append(dict(started_at=started,finished_at=finished,exit_code=0,complete=True,unfiltered=True,
            invocation_sha256=digest("synthetic-generator-not-EDA"),stdout_sha256=hashlib.sha256(text.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest()))
    return assemble(service,runs,executions,digest("synthetic-design"))
