import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from openwaiver.api import create_app
from openwaiver.cli import main, write_auth
from openwaiver.errors import Conflict, OpenWaiverError


@pytest.fixture
def client(service):
    auth=[{"name":name,"role":role,"sha256":hashlib.sha256((name+"-token").encode()).hexdigest()}
          for name,role in [("alice","contributor"),("bob","reviewer"),("reader","viewer"),("root","admin")]]
    return TestClient(create_app(service.store.path,auth))


def auth(name="alice"):
    return {"Authorization":f"Bearer {name}-token"}


def test_authentication_required(client):
    assert client.get("/health").status_code==200
    assert client.get("/api/runs").status_code==401
    assert client.get("/api/runs",headers={"Authorization":"Bearer wrong"}).status_code==401
    assert client.get("/api/me",headers=auth("bob")).json()["name"]=="bob"


def test_refuse_no_auth(service):
    with pytest.raises(OpenWaiverError):create_app(service.store.path,[])


def test_host_header_protected(client):
    assert client.get("/health",headers={"Host":"attacker.test"}).status_code==400


def test_cross_origin_write_protected(client):
    r=client.post("/api/runs",headers={**auth(),"Origin":"https://attacker.test"},json={})
    assert r.status_code==403


def test_api_import_and_search(client,record):
    body={"content":json.dumps({"schema_version":1,"violations":[record]}),"format":"json",
          "scope":{"project":"p","stream":"lint","tool":"verilator"},"revision":"abc", "complete":True,"checked_categories":["lint"]}
    r=client.post("/api/runs",json=body,headers=auth())
    assert r.status_code==201,r.text
    id=r.json()["id"]
    result=client.get(f"/api/runs/{id}/assessment?q=width&status=open",headers=auth("reader"))
    assert result.json()["total"]==1
    assert client.get(f"/api/runs/{id}/assessment?q=absent",headers=auth()).json()["total"]==0
    assert client.post("/api/runs",json=body,headers=auth("reader")).status_code==403


def test_api_actor_spoof_rejected(client,make_run):
    r=make_run()
    body={"run_id":r.id,"violation_id":"v1","rationale":"Long engineering justification", "owner":"alice","reviewers":["bob"],"valid_revision":r.revision,"actor":"root"}
    assert client.post("/api/waivers",headers=auth(),json=body).status_code==422


def test_api_review_role_and_version(client,make_run,make_waiver):
    w=make_waiver(make_run(),approve=False)
    url=f"/api/waivers/{w.id}/review"
    body={"version":w.version,"decision":"approve","comment":"Independent review accepted"}
    assert client.post(url,headers=auth(),json=body).status_code==403
    r=client.post(url,headers=auth("bob"),json=body)
    assert r.status_code==200 and r.json()["status"]=="approved"
    assert client.post(url,headers=auth("bob"),json=body).status_code==409


def test_readonly_user_cannot_change_policy(client):
    policy=client.get("/api/policy",headers=auth("reader")).json()
    assert client.put("/api/policy",headers=auth("reader"),json=policy).status_code==403


def test_security_headers_and_static_app(client):
    r=client.get("/")
    assert r.status_code==200 and "OpenWaiver" in r.text
    assert r.headers["x-content-type-options"]=="nosniff"
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code==200


def test_no_source_root_from_api(client,record):
    body={"content":"{}","format":"json","scope":{"project":"p","stream":"s","tool":"t"},"revision":"r","source_root":"/"}
    assert client.post("/api/runs",json=body,headers=auth()).status_code==422


def test_concurrent_edits_only_one_wins(service,actors,make_run,make_waiver):
    w=make_waiver(make_run(),approve=False,submit=False)
    def amend(tag):
        try:
            service.amend(actors["alice"],w.id,w.version,{"tags":[tag]})
            return "ok"
        except Conflict:return "conflict"
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(amend,["a","b"]))==["conflict","ok"]
    with service.store.transaction(write=False) as c:assert service.store.verify(c)["valid"]


def test_cli_gate_exit_codes(service,make_run,capsys):
    r=make_run()
    assert main(["--db",str(service.store.path),"gate",r.id])==1
    empty=make_run([])
    assert main(["--db",str(service.store.path),"gate",empty.id])==0
    assert main(["--db",str(service.store.path),"gate","missing"] )==2


def test_cli_auth_registry(tmp_path):
    path=tmp_path/"auth.json"
    token=write_auth(path,"alice","contributor")
    text=path.read_text()
    assert token not in text
    assert hashlib.sha256(token.encode()).hexdigest() in text
    assert path.stat().st_mode&0o777==0o600


def test_native_adapter_namespace_validated(service,actors):
    from openwaiver.models import Scope
    with pytest.raises(OpenWaiverError):
        service.import_run(actors["alice"],content="",format="verilator",scope=Scope(project="p",stream="s",tool="other"),revision="x")


def test_authenticated_api_entire_review_and_evidence_workflow(client, record):
    import base64
    body={'content':json.dumps({'schema_version':1,'violations':[record]}), 'format':'json',
          'scope':{'project':'chip','stream':'nightly','tool':'verilator'},'revision':'rev-a',
          'complete':True,'checked_categories':['lint']}
    run=client.post('/api/runs',json=body,headers=auth()).json()
    rid=run['id']
    assert client.get('/api/runs',headers=auth()).json()['total']==1
    proposal={'run_id':rid,'violation_id':'v1','rationale':'Engineering evidence supports this bounded exception.',
              'owner':'alice','reviewers':['bob'],'valid_revision':'rev-a'}
    r=client.post('/api/waivers',json=proposal,headers=auth());assert r.status_code==201,r.text
    w=r.json();wid=w['id']
    assert client.get('/api/waivers',headers=auth('reader')).json()['total']==1
    assert client.get(f'/api/waivers/{wid}',headers=auth('reader')).json()['id']==wid
    assert client.post(f'/api/waivers/{wid}/submit',json={'version':w['version']},headers=auth()).status_code==400
    evidence={'version':w['version'],'filename':'proof.txt','content_base64':base64.b64encode(b'engineering evidence').decode()}
    w=client.post(f'/api/waivers/{wid}/evidence',json=evidence,headers=auth()).json()
    sha=w['evidence'][0]['sha256']
    r=client.get(f'/api/evidence/{sha}',headers=auth('reader'))
    assert r.status_code==200 and r.content==b'engineering evidence'
    assert r.headers['content-disposition'].startswith('attachment;')
    w=client.post(f'/api/waivers/{wid}/submit',json={'version':w['version']},headers=auth()).json()
    assert w['status']=='submitted'
    w=client.post(f'/api/waivers/{wid}/review',json={'version':w['version'],'decision':'approve','comment':'Independent review accepted'},headers=auth('bob')).json()
    assert w['status']=='approved'
    assert client.get(f'/api/runs/{rid}/assessment?category=lint',headers=auth()).json()['gate_pass']
    s=client.post('/api/snapshots',json={'run_id':rid,'name':'A','require_clean':True},headers=auth('bob')).json()
    sid=s['id']
    assert client.get('/api/snapshots',headers=auth()).json()[0]['id']==sid
    data=client.get(f'/api/snapshots/{sid}/bundle',headers=auth()).content
    from openwaiver.interchange import verify_bundle
    assert verify_bundle(data)['valid']
    assert client.get(f'/api/compare/{sid}/{sid}',headers=auth()).json()['occurrences_added']==0
    assert client.get(f'/api/waivers/{wid}/history',headers=auth()).json()[-1]['action']=='approve'
    assert client.get('/api/audit',headers=auth()).json()['valid']
    manifest={'project':'chip','revision':'rev-a','checks':[{'stream':'nightly','tool':'verilator','categories':['lint'],'run_id':rid}]}
    assert client.post('/api/release-gate',json=manifest,headers=auth('reader')).json()['gate_pass']
    w=client.post(f'/api/waivers/{wid}/amend',json={'version':w['version'],'changes':{'rationale':'New engineering conditions need fresh independent approval.'}},headers=auth()).json()
    assert w['status']=='proposed' and not w['approvals']
    assert not client.get(f'/api/runs/{rid}/assessment',headers=auth()).json()['gate_pass']
    w=client.post(f'/api/waivers/{wid}/rebind',json={'version':w['version'],'run_id':rid,'violation_id':'v1'},headers=auth()).json()
    assert w['status']=='proposed'
    w=client.post(f'/api/waivers/{wid}/revoke',json={'version':w['version'],'comment':'The exception is no longer needed'},headers=auth()).json()
    assert w['status']=='revoked'
    assert client.get(f'/api/snapshots/{sid}/bundle',headers=auth()).content==data


@pytest.mark.parametrize('fmt', ['json','sarif','html','junit'])
def test_api_export_formats(client, make_run, fmt):
    run=make_run()
    r=client.get(f'/api/runs/{run.id}/export/{fmt}',headers=auth())
    assert r.status_code==200 and r.content
    assert r.headers['content-disposition'].startswith('attachment;')


def test_api_invalid_attachment_and_missing_evidence(client, make_run, make_waiver):
    w=make_waiver(make_run(),approve=False,submit=False)
    r=client.post(f'/api/waivers/{w.id}/evidence',json={'version':w.version,'filename':'x.txt','content_base64':'not-base64'},headers=auth())
    assert r.status_code==400
    assert client.get('/api/evidence/'+'0'*64,headers=auth()).status_code==404


def test_api_admin_policy_update(client):
    p=client.get('/api/policy',headers=auth('root')).json()
    p['min_approvals']=2
    r=client.put('/api/policy',json=p,headers=auth('root'))
    assert r.status_code==200 and r.json()['min_approvals']==2


def test_examples_are_parseable():
    from pathlib import Path
    from openwaiver.importers import parse_report
    root=Path(__file__).resolve().parents[1]/'examples'
    for filename,fmt in [('violations.json','json'),('violations.csv','csv'),('violations.xml','xml'),('violations.txt','text'),('verilator.log','verilator'),('report.lyrdb','klayout'),('report.sarif','sarif')]:
        assert len(parse_report((root/filename).read_text(),fmt))==1,(filename,fmt)


def test_demo_all_nine_categories_and_stable_bundle(tmp_path):
    from openwaiver.demo import seed
    from openwaiver.store import Store
    from openwaiver.service import Service
    result=seed(tmp_path/'demo.sqlite3')
    svc=Service(Store(result['database']))
    a=svc.assessment(result['current_run'])
    assert a['counts']=={'needs_review':2,'waived':2,'stale':1,'pending':2,'open':3}
    assert len(a['violations'])==10
    with pytest.raises(ValueError):
        seed(tmp_path/'demo.sqlite3')
