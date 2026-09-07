#!/usr/bin/env python3
"""Run actual Verilator and KLayout checks, then replay a signed two-tool release.

Only the installed executable/library and these synthetic inputs are qualified.
Keys stay in process memory; output includes no credentials or private design data.
"""
from datetime import timedelta
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from openwaiver.assurance import capture_inventory, evaluate_contract
from openwaiver.capsule import seal_capsule, verify_capsule
from openwaiver.identity import canonical, digest
from openwaiver.models import Principal, Scope, utcnow
from openwaiver.service import Service
from openwaiver.store import Store
from release_fixture import assemble


def main():
    import klayout.db as db
    executable=shutil.which("verilator")
    if not executable: raise RuntimeError("native Verilator is required; no silent skips")
    tool_version=subprocess.check_output([executable,"--version"],text=True,timeout=30).strip()
    with tempfile.TemporaryDirectory(prefix="ow-native-release-") as folder:
        root=Path(folder)
        source=root/"top.sv"
        source.write_text("module top(output wire y);\n wire unconsumed_a;\n assign y = 1'b0;\nendmodule\n")
        layout=db.Layout();layout.dbu=.001
        top=layout.create_cell("TOP");layer=layout.layer(1,0)
        top.shapes(layer).insert(db.Box(0,0,100,1000))
        layout_path=root/"layout.gds";layout.write(str(layout_path))
        design=digest({"top.sv":hashlib.sha256(source.read_bytes()).hexdigest(),
                       "layout.gds":hashlib.sha256(layout_path.read_bytes()).hexdigest()})
        service=Service(Store(root/"workspace.sqlite3"))
        actor=Principal(name="fixture-engineer",role="contributor")
        argv=[executable,"--lint-only","--Wall","-Wno-fatal","--top-module","top","top.sv"]
        start=utcnow()
        proc=subprocess.run(argv,cwd=root,capture_output=True,text=True,timeout=60)
        finish=utcnow()
        assert proc.returncode==0,proc.stderr
        run=service.import_run(actor,content=proc.stdout+proc.stderr,format="verilator",source_root=root,
            scope=Scope(project="native-fixture",stream="lint",tool="verilator"),revision="candidate-A",
            tool_version=tool_version,rule_deck_digest=digest("--Wall"),configuration_digest=digest(argv),
            complete=True,checked_categories=["lint"])
        assert len(run.violations)==1,"native lint fixture must actually emit its warning"
        executions=[dict(started_at=start,finished_at=finish,exit_code=proc.returncode,complete=True,unfiltered=True,
            invocation_sha256=digest(argv),stdout_sha256=hashlib.sha256(proc.stdout.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(proc.stderr.encode()).hexdigest())]
        start=utcnow()
        reread=db.Layout();reread.read(str(layout_path))
        native_pairs=list(db.Region(reread.cell("TOP").begin_shapes_rec(reread.find_layer(1,0))).width_check(120).each())
        finish=utcnow()
        assert native_pairs,"native width check must actually find the narrow polygon"
        records=[]
        for i,pair in enumerate(native_pairs):
            geometry=[dict(kind="edge",unit="dbu",layer="1/0",frame="TOP",
                           points=[[e.p1.x,e.p1.y],[e.p2.x,e.p2.y]]) for e in (pair.first,pair.second)]
            records.append(dict(id=f"width-{i}",category="drc",rule="WIDTH.120",hierarchy="TOP",
                                message="Actual KLayout width_check(120)",geometries=geometry))
        report=canonical(dict(schema_version=1,violations=records))
        invocation=dict(operation="Region.width_check",width_dbu=120,layer="1/0",dbu=.001)
        physical=service.import_run(actor,content=report,format="json",
            scope=Scope(project="native-fixture",stream="drc",tool="klayout"),revision="candidate-A",
            tool_version=version("klayout"),rule_deck_digest=digest("width_check(120)"),configuration_digest=digest(invocation),
            complete=True,checked_categories=["drc"])
        executions.append(dict(started_at=start,finished_at=finish,exit_code=0,complete=True,unfiltered=True,
            invocation_sha256=digest(invocation),stdout_sha256=hashlib.sha256(report.encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest()))
        contract,trust,receipts,key,now=assemble(service,[run,physical],executions,design)
        inventory=capture_inventory(service,contract)
        assert not evaluate_contract(contract,**inventory,receipts=receipts[:1],trust=trust,now=now)["gate_pass"]
        checked=evaluate_contract(contract,**inventory,receipts=receipts,trust=trust,now=now)
        assert checked["gate_pass"],checked
        capsule=seal_capsule(service,contract,receipts,trust,key,now=now,hours=72)
        verified=verify_capsule(capsule,contract,trust,now)
        assert verified["frozen_state_gate_pass_now"] and verified["historical_assessment_replayed"]
        old=verify_capsule(capsule,contract,trust,now+timedelta(hours=25))
        assert old["historical_gate_pass"] and not old["frozen_state_gate_pass_now"]
        result={"passed":True,"synthetic_only":True,"tools":{"verilator":tool_version,"klayout":version("klayout")},
            "checks":["native Verilator diagnostic","native GDS read and KLayout width check",
                      "independent waiver review for both streams","missing receipt blocks release",
                      "two-signer role separation and approved contract","signed capsule offline replay",
                      "historically clean release becomes unusable when execution receipts age"],
            "waived_findings":checked["risk"]["waived_findings"],"capsule_bytes":len(capsule),
            "qualification_scope":"Installed native versions and exercised synthetic fixtures only, not proprietary-tool qualification."}
    out=ROOT/"validation-results"/"native-release.json";out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))


if __name__=="__main__":main()
