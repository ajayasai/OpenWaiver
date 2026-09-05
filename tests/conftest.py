from datetime import timedelta
import hashlib
import json

import pytest

from openwaiver.models import Principal, Scope, utcnow
from openwaiver.service import Service
from openwaiver.store import Store


@pytest.fixture
def actors():
    return {"alice": Principal(name="alice", role="contributor"),
            "bob": Principal(name="bob", role="reviewer"),
            "carol": Principal(name="carol", role="reviewer"),
            "root": Principal(name="root", role="admin"),
            "reader": Principal(name="reader", role="viewer")}


@pytest.fixture
def service(tmp_path):
    return Service(Store(tmp_path / "workspace.sqlite3"))


@pytest.fixture
def record():
    return {"id": "v1", "category": "lint", "rule": "WIDTH", "severity": "warning",
            "message": "Signal has width 32, expected 16", "hierarchy": "top/u1",
            "path": "rtl/top.sv", "line": 21, "column": 2,
            "context_hash": hashlib.sha256(b"surrounding RTL").hexdigest()}


@pytest.fixture
def make_run(service, actors, record):
    def make(values=None, revision="rev-a", **kwargs):
        values = [dict(record)] if values is None else values
        scope = kwargs.pop("scope", Scope(project="chip", stream="nightly", tool="verilator"))
        checked = kwargs.pop("checked_categories", list(dict.fromkeys(v["category"] for v in values)) or ["lint"])
        complete = kwargs.pop("complete", True)
        return service.import_run(actors["alice"], content=json.dumps({"schema_version": 1, "violations": values}),
            format="json", scope=scope, revision=revision, complete=complete, checked_categories=checked, **kwargs)
    return make


@pytest.fixture
def make_waiver(service, actors):
    def make(run, *, approve=True, submit=True, evidence=True, reviewers=None, **kwargs):
        w = service.propose(actors["alice"], run_id=run.id, violation_id=run.violations[0].id,
            rationale="Engineering review confirms this bounded exception is acceptable.", owner="alice",
            reviewers=reviewers or ["bob"], expires_on=kwargs.pop("expires_on", utcnow().date()+timedelta(days=30)), **kwargs)
        if evidence:
            w = service.attach(actors["alice"], w.id, w.version, "evidence.txt", b"Detailed engineering evidence")
        if submit:
            w = service.submit(actors["alice"], w.id, w.version)
        if approve:
            for name in w.reviewers:
                w = service.review(actors[name], w.id, w.version, "approve", "Independent engineering review accepted.")
        return w
    return make
