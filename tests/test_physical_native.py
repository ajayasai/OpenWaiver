"""Actual native-library checks. CI installs the physical extra; no native stubs."""
from datetime import timedelta
import hashlib
from importlib.metadata import version
import json

import pytest

db = pytest.importorskip("klayout.db", reason="native KLayout tests require openwaiver[physical]")

from openwaiver.errors import OpenWaiverError
from openwaiver.identity import canonical, fingerprint
from openwaiver.models import Principal, Scope, utcnow
from openwaiver.physical import Placement, context_hash
from openwaiver.physical_native import extract_layout


def make_layout(tmp_path, extension="gds", *, rotation=0, mirror=False, repeat=False, complex=False, extra=None):
    layout = db.Layout();layout.dbu = .001
    top=layout.create_cell("TOP"); cell=layout.create_cell("MACRO")
    m1=layout.layer(1,0);m2=layout.layer(2,0)
    cell.shapes(m1).insert(db.Box(0,0,100,400))
    polygon=db.Polygon([db.Point(140,0),db.Point(300,0),db.Point(300,400),db.Point(140,400)])
    polygon.insert_hole([db.Point(180,100),db.Point(250,100),db.Point(250,300),db.Point(180,300)])
    cell.shapes(m2).insert(polygon)
    t=db.ICplxTrans(1.25 if complex else 1, rotation,mirror,1000,500)
    top.insert(db.CellInstArray(cell.cell_index(),t))
    if repeat:top.insert(db.CellInstArray(cell.cell_index(),db.Trans(4000,500)))
    if extra=="text":cell.shapes(m2).insert(db.Text("not silently discarded",db.Trans(150,200)))
    if extra=="path":cell.shapes(m2).insert(db.Path([db.Point(150,100),db.Point(200,300)],10))
    path=tmp_path/("layout."+extension);layout.write(str(path))
    record={"id":"native-width","category":"drc","rule":"WIDTH.120","message":"Native minimum width check",
        "hierarchy":"MACRO","geometries":[{"kind":"edge","unit":"dbu","points":[[0,0],[0,400]]},
                                             {"kind":"edge","unit":"dbu","points":[[100,0],[100,400]]}]}
    content=canonical({"schema_version":1,"violations":[record]})
    return path,content,layout


def extract(path, content, **kwargs):
    opts=dict(layout_path=path,content=content,format="json",scope=Scope(project="chip",tool="klayout",stream="physical"),
        revision="A",top_cell="TOP",layers=["1/0","2/0"],halo_dbu=500)
    opts.update(kwargs)
    return extract_layout(**opts)


@pytest.mark.parametrize("extension",["gds","oas"])
@pytest.mark.parametrize("rotation,mirror",[(0,False),(90,False),(180,True),(270,True)])
def test_real_layout_read_and_hierarchical_placement(tmp_path,extension,rotation,mirror):
    path,content,layout=make_layout(tmp_path,extension,rotation=rotation,mirror=mirror)
    manifest=extract(path,content)
    n=manifest.targets["native-width"]
    assert n.placement==Placement(rotation=rotation,mirror=mirror,dx=1000,dy=500)
    assert len(n.shapes)>=2 and {p.layer for p in n.shapes}=={"1/0","2/0"}
    assert manifest.layout_sha256==hashlib.sha256(path.read_bytes()).hexdigest()
    assert manifest.recipe.producer=="klayout-python/"+version("klayout")
    # Native width_check is actually executed, rather than reporting a handmade pass.
    reread=db.Layout();reread.read(str(path))
    region=db.Region(reread.cell("TOP").begin_shapes_rec(reread.find_layer(1,0)))
    assert region.width_check(120).size()>=1


def test_ambiguous_replicas_and_explicit_selection(tmp_path):
    path,content,_=make_layout(tmp_path,repeat=True)
    with pytest.raises(OpenWaiverError,match="ambiguous"):extract(path,content)
    m=extract(path,content,placements={"native-width":{"dx":1000,"dy":500}})
    assert m.targets["native-width"].placement.dx==1000
    with pytest.raises(OpenWaiverError):extract(path,content,placements={"native-width":{"dx":1001,"dy":500}})
    with pytest.raises(OpenWaiverError):extract(path,content,placements={"unknown":{}})


@pytest.mark.parametrize("extra",["text","path"])
def test_unsupported_native_shape_fails_instead_of_disappearing(tmp_path,extra):
    path,content,_=make_layout(tmp_path,extra=extra)
    with pytest.raises(OpenWaiverError,match="unsupported native shape"):extract(path,content)


@pytest.mark.parametrize("kwargs",[{"complex":True},{"rotation":45}])
def test_native_nonorthogonal_transform_rejected(tmp_path,kwargs):
    path,content,_=make_layout(tmp_path,**kwargs)
    with pytest.raises(OpenWaiverError,match="rounding"):extract(path,content)


@pytest.mark.parametrize("kwargs",[{"top_cell":"MISSING"},{"layers":["99/0"]},{"layers":["01/0"]},
                                  {"layers":["metal"]},{"layers":["65536/0"]}])
def test_native_declared_coverage_must_exist(tmp_path,kwargs):
    path,content,_=make_layout(tmp_path)
    with pytest.raises(OpenWaiverError):extract(path,content,**kwargs)


def test_native_nonexistent_file_and_symlink(tmp_path):
    path,content,_=make_layout(tmp_path)
    link=tmp_path/"link.gds";link.symlink_to(path)
    with pytest.raises(OpenWaiverError):extract(link,content)
    path.unlink()
    with pytest.raises(OpenWaiverError):extract(path,content)


def test_native_context_change_blocks_existing_approval(tmp_path,service,actors):
    path,_,layout=make_layout(tmp_path)
    top=layout.cell("TOP");layer=layout.find_layer(1,0)
    pairs=list(db.Region(top.begin_shapes_rec(layer)).width_check(120).each())
    assert pairs, "actual native rule must produce a finding"
    records=[]
    for i,pair in enumerate(pairs):
        geometries=[]
        for edge in (pair.first,pair.second):
            geometries.append(dict(kind="edge",unit="dbu",points=[[edge.p1.x,edge.p1.y],[edge.p2.x,edge.p2.y]]))
        records.append(dict(id=f"native-{i}",category="drc",rule="WIDTH.120",hierarchy="TOP",
                            message="Actual KLayout width_check(120) result",geometries=geometries))
    content=canonical(dict(schema_version=1,violations=records))
    m=extract(path,content)
    def import_run(manifest):
        return service.import_run(actors["alice"],content=content,format="json",scope=m.scope,
            revision=manifest.revision,complete=True,checked_categories=["drc"],tool_version=version("klayout"),
            physical_manifest=manifest.model_dump(mode="json"))
    baseline=import_run(m)
    for v in baseline.violations:
        w=service.propose(actors["alice"],run_id=baseline.id,violation_id=v.id,owner="alice",reviewers=["bob"],
            rationale="Independent synthetic native-engine conformance exception.",expires_on=utcnow().date()+timedelta(days=10))
        w=service.attach(actors["alice"],w.id,w.version,"evidence.json",canonical(m).encode())
        w=service.submit(actors["alice"],w.id,w.version)
        service.review(actors["bob"],w.id,w.version,"approve","Synthetic independent review complete.")
    assert service.assessment(baseline.id)["gate_pass"]
    # Alter a second-layer neighbor; the first-layer rule finding is unchanged.
    layout.cell("MACRO").shapes(layout.find_layer(2,0)).insert(db.Box(110,100,130,120))
    layout.write(str(path))
    changed=extract(path,content,revision="B")
    after=import_run(changed)
    assert [fingerprint(v) for v in baseline.violations]==[fingerprint(v) for v in after.violations]
    result=service.assessment(after.id)
    assert result["counts"]=={"stale":len(pairs)} and not result["gate_pass"]
    out=tmp_path/"native-physical-result.json"
    out.write_text(json.dumps(dict(klayout_version=version("klayout"),passed=True,synthetic_only=True,
                                  native_markers=len(pairs),changed_neighbors_blocked=True),indent=2))
