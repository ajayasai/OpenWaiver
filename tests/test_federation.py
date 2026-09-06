from copy import deepcopy
import json
import time

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest

from openwaiver.federation import (FederationConfig, FederationUnavailable, InvalidAccessToken,
    load_config, strict_object, validate_access_token)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def federation(signing_key):
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
    public.update(kid="key-1", alg="RS256", use="sig", key_ops=["verify"])
    config = dict(issuer="https://identity.example.test/realms/engineering", audience="openwaiver-api",
        jwks={"keys": [public]}, bindings=[dict(subject="opaque-alice", client_ids=["eda-client"],
            principal=dict(name="alice", role="contributor", projects=["chip"]))])
    now = int(time.time())
    claims = dict(iss=config["issuer"], aud=config["audience"], sub="opaque-alice", client_id="eda-client",
                  iat=now-5, exp=now+300, jti="one-session", scope="openwaiver")
    return config, claims


def token(signing_key, claims, **headers):
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "key-1", "typ": "at+jwt", **headers})


def test_valid_token_never_trusts_roles_or_project_claims(signing_key, federation):
    c, claims = federation; claims.update(roles=["admin"], projects=["other"], email="root@example.test")
    result = validate_access_token(token(signing_key, claims), FederationConfig.model_validate(c))
    assert (result.name, result.role, result.projects) == ("alice", "contributor", ["chip"])


@pytest.mark.parametrize("claim,value", [("iss", "https://evil.test"), ("aud", "other-api"),
    ("aud", ["openwaiver-api", "other-api"]), ("sub", "unbound"), ("client_id", "other-client"),
    ("jti", ""), ("scope", "openid profile"), ("scope", ["openwaiver"]), ("iat", 1),
    ("iat", "1"), ("iat", True), ("exp", 1), ("exp", "9999999999"), ("nbf", True),
    ("nbf", 9999999999), ("iat", 9999999999), ("exp", 9999999999)])
def test_claim_attacks_rejected(signing_key, federation, claim, value):
    c, claims = federation; claims[claim] = value
    with pytest.raises(InvalidAccessToken): validate_access_token(token(signing_key, claims), FederationConfig.model_validate(c))


@pytest.mark.parametrize("missing", ["iss", "aud", "sub", "client_id", "iat", "exp", "jti"])
def test_required_claims(signing_key, federation, missing):
    c, claims = federation; del claims[missing]
    with pytest.raises(InvalidAccessToken): validate_access_token(token(signing_key, claims), FederationConfig.model_validate(c))


@pytest.mark.parametrize("headers", [{"typ": "JWT"}, {"kid": "unknown"},
    {"jku": "https://evil.test/jwks"}, {"jwk": {"kty": "RSA"}}, {"crit": ["exp"]}, {"b64": False}])
def test_id_tokens_and_dynamic_key_headers_rejected(signing_key, federation, headers):
    c, claims = federation
    with pytest.raises(InvalidAccessToken): validate_access_token(token(signing_key, claims, **headers), FederationConfig.model_validate(c))


def test_algorithm_confusion_bad_signature_and_duplicate_json(signing_key, federation):
    c, claims = federation; config = FederationConfig.model_validate(c)
    for raw in [jwt.encode(claims, "not-a-public-key-not-a-public-key", algorithm="HS256", headers={"typ":"at+jwt","kid":"key-1"}),
                jwt.encode(claims, "", algorithm="none", headers={"typ":"at+jwt","kid":"key-1"}),
                token(signing_key, claims).rsplit(".", 1)[0] + ".AAAA", "broken", "a" * 17000]:
        with pytest.raises(InvalidAccessToken): validate_access_token(raw, config)
    h = jwt.utils.base64url_encode(b'{"alg":"RS256","alg":"none","kid":"key-1","typ":"at+jwt"}').decode()
    payload = jwt.utils.base64url_encode(json.dumps(claims).encode()).decode()
    with pytest.raises(InvalidAccessToken): validate_access_token(h+"."+payload+".AAAA", config)
    with pytest.raises(ValueError): strict_object('{"x":1,"x":2}')
    with pytest.raises(ValueError): strict_object('{"x":NaN}')


@pytest.mark.parametrize("kind", ["jti", "subject", "cutoff"])
def test_revocation(signing_key, federation, kind):
    c, claims = federation
    if kind == "jti": c["revoked_jtis"] = [claims["jti"]]
    if kind == "subject": c["disabled_subjects"] = [claims["sub"]]
    if kind == "cutoff": c["issued_after"] = {claims["sub"]: claims["iat"]+1}
    with pytest.raises(InvalidAccessToken): validate_access_token(token(signing_key, claims), FederationConfig.model_validate(c))


@pytest.mark.parametrize("kind", ["http", "issuerquery", "emptykeys", "private", "duplicatekid", "duplicatebinding",
    "wildcard", "algorithm", "use", "keyops", "scope", "aliasgrants", "smallkey", "clients"])
def test_invalid_trust_configuration(signing_key, federation, kind):
    c, _ = federation
    if kind == "http": c["issuer"] = "http://identity.test"
    if kind == "issuerquery": c["issuer"] += "?bypass=true"
    if kind == "emptykeys": c["jwks"]["keys"] = []
    if kind == "private": c["jwks"]["keys"][0]["d"] = "private-data"
    if kind == "duplicatekid": c["jwks"]["keys"] *= 2
    if kind == "duplicatebinding": c["bindings"] *= 2
    if kind == "wildcard": c["bindings"][0]["principal"]["projects"] = None
    if kind == "algorithm": c["jwks"]["keys"][0]["alg"] = "HS256"
    if kind == "use": c["jwks"]["keys"][0]["use"] = "enc"
    if kind == "keyops": c["jwks"]["keys"][0]["key_ops"] = ["sign"]
    if kind == "scope": c["required_scopes"] = ["two words"]
    if kind == "clients": c["bindings"][0]["client_ids"] = ["same", "same"]
    if kind == "aliasgrants":
        alias = deepcopy(c["bindings"][0]); alias["subject"] = "second"; alias["principal"]["role"] = "admin"; c["bindings"].append(alias)
    if kind == "smallkey":
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        c["jwks"]["keys"][0].update(json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())))
    with pytest.raises((ValueError, jwt.PyJWTError)): FederationConfig.model_validate(c)


def test_config_reload_and_fail_closed(signing_key, federation, tmp_path):
    c, claims = federation; path = tmp_path / "trust.json"; path.write_text(json.dumps(c))
    raw = token(signing_key, claims)
    assert validate_access_token(raw, load_config(path)).name == "alice"
    c["disabled_subjects"] = [claims["sub"]]; path.write_text(json.dumps(c))
    with pytest.raises(InvalidAccessToken): validate_access_token(raw, load_config(path))
    for content in ['{}', '{"jwks":{},"jwks":{}}', 'x'*(2*1024*1024+1)]:
        path.write_text(content)
        with pytest.raises(FederationUnavailable): load_config(path)
    path.unlink()
    with pytest.raises(FederationUnavailable): load_config(path)


def test_api_federated_lifecycle_physical_isolation_and_live_revocation(signing_key, federation, tmp_path):
    import base64
    import hashlib
    from fastapi.testclient import TestClient
    from openwaiver.api import create_app
    from test_physical import fixture
    c, claims = federation
    c["bindings"].append(dict(subject="opaque-bob", client_ids=["eda-client"],
        principal=dict(name="bob", role="reviewer", projects=["chip"])))
    path = tmp_path / "trust.json"; path.write_text(json.dumps(c))
    app = create_app(tmp_path / "workspace.sqlite3", federation_file=path)
    client = TestClient(app)
    owner = {"Authorization": "Bearer " + token(signing_key, claims)}
    reviewer = {"Authorization": "Bearer " + token(signing_key, {**claims, "sub":"opaque-bob", "jti":"bob-session"})}
    assert client.get("/api/me", headers=owner).json()["projects"] == ["chip"]
    v, manifest, content = fixture()
    body = dict(content=content, format="json", scope=manifest.scope.model_dump(), revision="A",
        complete=True, checked_categories=["drc"], physical_manifest=manifest.model_dump(mode="json"))
    response = client.post("/api/runs", json=body, headers=owner)
    assert response.status_code == 201, response.text
    run = response.json()
    assert "physical_manifest" not in client.get("/api/runs",headers=owner).json()["items"][0]
    inspect = client.get(f"/api/runs/{run['id']}/physical/{v.id}",headers=reviewer)
    assert inspect.status_code == 200 and len(inspect.json()["shapes"][0]["holes"]) == 1
    proposal = dict(run_id=run["id"],violation_id=v.id,rationale="Reviewed synthetic physical constraint exception.",
                    owner="alice",reviewers=["bob"],valid_revision="A")
    w = client.post("/api/waivers",json=proposal,headers=owner).json()
    w = client.post(f"/api/waivers/{w['id']}/evidence",headers=owner,
        json=dict(version=w["version"],filename="reason.txt",content_base64=base64.b64encode(b"Synthetic engineering evidence").decode())).json()
    w = client.post(f"/api/waivers/{w['id']}/submit",json=dict(version=w["version"]),headers=owner).json()
    own_decision = client.post(f"/api/waivers/{w['id']}/review",headers=owner,
        json=dict(version=w["version"],decision="approve",comment="Cannot self approve."))
    assert own_decision.status_code == 403
    response = client.post(f"/api/waivers/{w['id']}/review",headers=reviewer,
        json=dict(version=w["version"],decision="approve",comment="Independent review completed."))
    assert response.status_code == 200 and response.json()["status"] == "approved"
    assert client.get(f"/api/runs/{run['id']}/assessment",headers=owner).json()["gate_pass"]
    denied = deepcopy(body); denied["scope"]["project"] = "other"
    assert client.post("/api/runs",json=denied,headers=owner).status_code == 404
    assert client.get("/api/physical/compare/not-authorized/not-authorized",headers=owner).status_code == 404
    assert client.get(f"/api/runs/{run['id']}/physical/{v.id}").status_code == 401
    c["disabled_subjects"]=["opaque-alice"];path.write_text(json.dumps(c))
    assert client.get("/api/me",headers=owner).status_code == 401
    assert client.get("/api/me",headers=reviewer).status_code == 200
    path.write_text("{}");assert client.get("/api/me",headers=reviewer).status_code == 503
    assert client.get("/physical").status_code == 200


def test_api_invalid_jwt_never_falls_back_to_local_hash(signing_key, federation, tmp_path):
    import hashlib
    from fastapi.testclient import TestClient
    from openwaiver.api import create_app
    c, claims = federation; path=tmp_path/"trust.json";path.write_text(json.dumps(c))
    bad=token(signing_key,{**claims,"aud":"wrong"})
    auth=[dict(name="root",role="admin",sha256=hashlib.sha256(bad.encode()).hexdigest())]
    client=TestClient(create_app(tmp_path/"db.sqlite3",auth=auth,federation_file=path))
    assert client.get("/api/me",headers={"Authorization":"Bearer "+bad}).status_code==401


def test_api_federation_only_no_token_or_nonjwt(signing_key, federation, tmp_path):
    from fastapi.testclient import TestClient
    from openwaiver.api import create_app
    c,_=federation;path=tmp_path/"trust.json";path.write_text(json.dumps(c))
    client=TestClient(create_app(tmp_path/"db.sqlite3",federation_file=path))
    assert client.get("/api/me").status_code==401
    assert client.get("/api/me",headers={"Authorization":"Bearer random"}).status_code==401
    path.write_text("{}");
    with pytest.raises(FederationUnavailable):create_app(tmp_path/"other.sqlite3",federation_file=path)
