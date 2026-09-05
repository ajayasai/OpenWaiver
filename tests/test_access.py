from datetime import timedelta
import hashlib
import json

from fastapi.testclient import TestClient
import pytest

from openwaiver.access import token_records
from openwaiver.api import create_app
from openwaiver.cli import write_auth
from openwaiver.errors import Forbidden, NotFound
from openwaiver.models import Policy, Principal, Scope, utcnow


def headers():
    return {"Authorization": "Bearer scoped-token"}


def client_for(service, role="admin", projects=None):
    return TestClient(create_app(service.store.path, [{"name": "alice", "role": role,
        "sha256": hashlib.sha256(b"scoped-token").hexdigest(),
        "projects": ["chip"] if projects is None else projects}]))


@pytest.fixture
def projects(service, make_run, make_waiver, actors):
    own = make_run()
    foreign = make_run(scope=Scope(project="secret", stream="nightly", tool="verilator"))
    w1, w2 = make_waiver(own), make_waiver(foreign)
    s1 = service.freeze(actors["bob"], own.id, "public-to-chip")
    s2 = service.freeze(actors["bob"], foreign.id, "secret-candidate")
    return own, foreign, w1, w2, s1, s2


def test_lists_and_audit_filter_projects(service, projects):
    own, foreign, w1, w2, s1, s2 = projects
    client = client_for(service)
    runs = client.get("/api/runs", headers=headers()).json()
    assert runs["total"] == 1 and runs["items"][0]["id"] == own.id
    waivers = client.get("/api/waivers", headers=headers()).json()
    assert waivers["total"] == 1 and waivers["items"][0]["id"] == w1.id
    snaps = client.get("/api/snapshots", headers=headers()).json()
    assert [s["id"] for s in snaps] == [s1.id]
    audit = client.get("/api/audit", headers=headers()).json()
    assert audit["view"] == "project-filtered" and audit["head"] is None
    assert all(x not in json.dumps(audit) for x in [foreign.id, w2.id, s2.id, "secret-candidate"])


@pytest.mark.parametrize("route", ["assessment", "export", "waiver", "history", "compare"])
def test_guessed_foreign_ids_cannot_be_read(service, projects, route):
    own, foreign, w1, w2, s1, s2 = projects
    paths = {"assessment": f"/api/runs/{foreign.id}/assessment",
        "export": f"/api/runs/{foreign.id}/export/json", "waiver": f"/api/waivers/{w2.id}",
        "history": f"/api/waivers/{w2.id}/history", "compare": f"/api/compare/{s1.id}/{s2.id}"}
    response = client_for(service).get(paths[route], headers=headers())
    assert response.status_code == 404
    assert "secret" not in response.text


def test_foreign_evidence_hash_is_not_authorization(service, make_run, make_waiver, actors):
    own = make_run()
    foreign = make_run(scope=Scope(project="secret", stream="s", tool="t"))
    w = make_waiver(foreign, approve=False, submit=False, evidence=False)
    w = service.attach(actors["alice"], w.id, w.version, "private.txt", b"Secret evidence not shared with chip")
    assert client_for(service).get(f"/api/evidence/{w.evidence[0].sha256}", headers=headers()).status_code == 404
    assert client_for(service).get(f"/api/runs/{own.id}/assessment", headers=headers()).status_code == 200


def test_scoped_admin_cannot_change_shared_policy_or_download_shared_ledger(service, projects):
    client = client_for(service)
    assert client.put("/api/policy", headers=headers(), json=Policy().model_dump(mode="json")).status_code == 403
    assert client.get(f"/api/snapshots/{projects[4].id}/bundle", headers=headers()).status_code == 403


def test_empty_grants_give_no_projects(service, projects):
    client = client_for(service, projects=[])
    assert client.get("/api/runs", headers=headers()).json()["total"] == 0
    assert client.get("/api/waivers", headers=headers()).json()["total"] == 0


@pytest.mark.parametrize("operation", ["amend", "attach", "submit", "review", "revoke", "rebind"])
def test_service_mutations_enforce_project_boundary(service, projects, operation):
    _, foreign, _, w, _, _ = projects
    actor = Principal(name="alice", role="admin", projects=["chip"])
    calls = {
        "amend": lambda: service.amend(actor, w.id, w.version, {"tags": ["x"]}),
        "attach": lambda: service.attach(actor, w.id, w.version, "x.txt", b"x"),
        "submit": lambda: service.submit(actor, w.id, w.version),
        "review": lambda: service.review(actor, w.id, w.version, "approve", "reviewed"),
        "revoke": lambda: service.revoke(actor, w.id, w.version, "revoked"),
        "rebind": lambda: service.rebind(actor, w.id, w.version, foreign.id, "v1")}
    with pytest.raises(NotFound):
        calls[operation]()


def test_import_and_release_cannot_target_foreign_project(service):
    client = client_for(service)
    body = {"content": '{"schema_version":1,"violations":[]}', "format": "json",
            "scope": {"project": "secret", "stream": "s", "tool": "t"}, "revision": "r"}
    assert client.post("/api/runs", headers=headers(), json=body).status_code == 404
    manifest = {"project": "secret", "revision": "r", "checks": [{"stream": "s", "tool": "t", "categories": ["lint"]}]}
    assert client.post("/api/release-gate", headers=headers(), json=manifest).status_code == 404


def test_registry_reload_revocation_and_fail_closed(service, tmp_path):
    path = tmp_path / "auth.json"
    token = write_auth(path, "alice", "reviewer", projects=["chip"])
    client = TestClient(create_app(service.store.path, auth_file=path))
    auth = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/me", headers=auth).json()["projects"] == ["chip"]
    records = json.loads(path.read_text())
    records["tokens"][0]["revoked"] = True
    path.write_text(json.dumps(records))
    assert client.get("/api/me", headers=auth).status_code == 401
    path.write_text("broken registry")
    assert client.get("/api/me", headers=auth).status_code == 503


def test_expired_token_not_accepted(service, tmp_path):
    path = tmp_path / "auth.json"
    token = write_auth(path, "alice", "reviewer", projects=["chip"], expires_at=utcnow() - timedelta(seconds=1))
    client = TestClient(create_app(service.store.path, auth_file=path))
    assert client.get("/api/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@pytest.mark.parametrize("grants", [["chip", "chip"], [""], [" chip"], ["chip\n"]])
def test_malformed_project_grants_rejected(grants):
    with pytest.raises(ValueError):
        Principal(name="user", role="viewer", projects=grants)


def test_registry_rejects_unknown_fields_and_duplicate_tokens(tmp_path):
    path = tmp_path / "auth.json"
    write_auth(path, "alice", "viewer", projects=["chip"])
    record = json.loads(path.read_text())["tokens"][0]
    for records in [[record, record], [{**record, "sudo": True}]]:
        path.write_text(json.dumps({"tokens": records}))
        with pytest.raises(ValueError):
            token_records(path)
