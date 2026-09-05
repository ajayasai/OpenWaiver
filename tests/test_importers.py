import json
from pathlib import Path

import pytest

from openwaiver.errors import OpenWaiverError
from openwaiver.importers import parse_report, strict_json


def test_json(record):
    v=parse_report(json.dumps({"schema_version":1,"violations":[record]}),"json")[0]
    assert v.rule=="WIDTH" and v.line==21


@pytest.mark.parametrize("source", ['{"schema_version":1,"violations":[],"extra":1}',
    '{"schema_version":2,"violations":[]}', '{"schema_version":1,"violations":[],"violations":[]}',
    '{"schema_version":1,"violations":[', '[]'])
def test_malformed_json_never_clean(source):
    with pytest.raises(OpenWaiverError):
        parse_report(source,"json")


def test_duplicate_occurrence_ids(record):
    with pytest.raises(OpenWaiverError):
        parse_report(json.dumps({"schema_version":1,"violations":[record,record]}),"json")


def test_duplicate_fingerprints_preserved(record):
    rows=parse_report(json.dumps({"schema_version":1,"violations":[record,{**record,"id":"v2"}]}),"json")
    assert len(rows)==2


def test_csv():
    rows=parse_report('category,rule,message,path,line\nlint,WIDTH,"width, differs",top.sv,4\n',"csv")
    assert rows[0].message=="width, differs" and rows[0].line==4


@pytest.mark.parametrize("source", ["category,rule,rule,message\nlint,R,R,bad\n",
    "category,rule,message,path\nlint,R,bad,top.sv,extra\n",
    "category,rule,message,path\nlint,R\n", "nothing\n", "category,rule,message,junk\n"])
def test_invalid_csv(source):
    with pytest.raises(OpenWaiverError):
        parse_report(source,"csv")


def test_xml():
    rows=parse_report('<violations schema_version="1"><violation><category>drc</category><rule>R</rule><message>Marker</message><hierarchy>top</hierarchy></violation></violations>',"xml")
    assert rows[0].category=="drc"


@pytest.mark.parametrize("xml", [
    '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><violations schema_version="1">&e;</violations>',
    '<violations schema_version="1"><violation><rule>R</rule><rule>R2</rule></violation></violations>',
    '<report></report>', '<violations schema_version="1"><unknown/></violations>'
])
def test_hostile_xml(xml):
    with pytest.raises(OpenWaiverError):
        parse_report(xml,"xml")


def test_text():
    r=parse_report('lint|warning|WIDTH|top|rtl/a.sv|7|2|Width mismatch\n',"text")
    assert r[0].line==7


def test_garbage_text_is_error():
    with pytest.raises(OpenWaiverError):parse_report("Warnings: probably none", "text")


def test_verilator():
    rows=parse_report('%Warning-WIDTH: rtl/top.sv:3:9: Expected 32 bits\n    3 | assign x = y;\n%Error: Exiting due to 1 warning(s)\n',"verilator")
    assert rows[0].line==3 and "assign x" in rows[0].message


@pytest.mark.parametrize("source", ["%Error: Cannot open source", "%Error: Exiting due to 1 warning(s)", "unexpected format v99", "- Verilator: report summary"])
def test_invalid_verilator(source):
    with pytest.raises(OpenWaiverError):parse_report(source,"verilator")


def test_klayout_real_structure():
    source='''<report-database><items><item><category>'M2.SPACING'</category><cell>TOP:1</cell><multiplicity>3</multiplicity><tags>waived</tags><values><value>text: 'Marker'</value><value>polygon: (0,0;2,0;2,2;0,2)</value><value>edge: (1,1;2,2)</value></values></item></items></report-database>'''
    v=parse_report(source,"klayout")[0]
    assert len(v.geometries)==2 and v.multiplicity==3 and v.hierarchy=="TOP:1"
    assert v.metadata["klayout_tags_untrusted"]=="waived"


def test_klayout_unknown_geometry_not_silently_dropped():
    with pytest.raises(OpenWaiverError):parse_report('<report-database><items><item><values><value>edge-pair: (0,0;1,1)/(2,2;3,3)</value></values></item></items></report-database>',"klayout")


def test_sarif_preserves_external_suppression_as_untrusted():
    s={"version":"2.1.0","runs":[{"tool":{"driver":{"name":"lint"}},"results":[{"ruleId":"R","message":{"text":"bad"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"rtl/a%20b.sv"},"region":{"startLine":1}}}],"suppressions":[{"kind":"external","status":"accepted"}]}]}]}
    v=parse_report(json.dumps(s),"sarif")[0]
    assert v.path=="rtl/a b.sv" and v.metadata["sarif_suppressions_untrusted"]


def test_sarif_failed_run():
    with pytest.raises(OpenWaiverError):parse_report(json.dumps({"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":False}]}]}),"sarif")


def test_source_hash_and_traversal(tmp_path, record):
    root=tmp_path/"src";root.mkdir();(root/"x.sv").write_text("module x; endmodule")
    doc={"schema_version":1,"violations":[{**record,"path":"x.sv"}]}
    v=parse_report(json.dumps(doc),"json",source_root=root)[0]
    assert len(v.context_hash)==64
    outside=tmp_path/"outside.sv";outside.write_text("private")
    for path in ("../outside.sv",str(outside)):
        doc["violations"][0]["path"]=path
        with pytest.raises(OpenWaiverError):parse_report(json.dumps(doc),"json",source_root=root)
    (root/"link.sv").symlink_to(outside)
    doc["violations"][0]["path"]="link.sv"
    with pytest.raises(OpenWaiverError):parse_report(json.dumps(doc),"json",source_root=root)


def test_plugins_are_opt_in():
    with pytest.raises(OpenWaiverError):parse_report("whatever","third-party-parser")


@pytest.mark.parametrize("constant",["NaN","Infinity","-Infinity"])
def test_json_nonfinite(constant):
    with pytest.raises(OpenWaiverError):strict_json(constant)


def test_klayout_never_skips_unknown_records():
    from openwaiver.importers import parse_report
    from openwaiver.errors import OpenWaiverError
    for text in [
        '<report-database><items><unexpected/></items></report-database>',
        '<report-database><items/><items/></report-database>',
        '<report-database><items><item><cell>TOP</cell><category>A</category><category>B</category></item></items></report-database>',
        '<report-database><items><item><cell>TOP</cell><category>A</category><values><unknown/></values></item></items></report-database>',
    ]:
        with pytest.raises(OpenWaiverError):
            parse_report(text,'klayout')


def test_missing_sarif_results_is_not_clean():
    from openwaiver.importers import parse_report
    from openwaiver.errors import OpenWaiverError
    with pytest.raises(OpenWaiverError):
        parse_report('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}}}]}','sarif')
