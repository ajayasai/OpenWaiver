"""Operator CLI validates bound evidence and never invents a complete EDA run."""
import json
from pathlib import Path
from openwaiver.identity import canonical
from openwaiver.physical_cli import main, read
from test_physical import fixture


def arguments(tmp_path, manifest):
    _, _, content = fixture()
    report = tmp_path/'report.json';report.write_text(content)
    evidence = tmp_path/'physical.json';evidence.write_text(canonical(manifest))
    return ['import','--db',str(tmp_path/'db.sqlite3'),'--actor','operator','--manifest',str(evidence),
            '--report',str(report),'--format','json','--project',manifest.scope.project,
            '--tool',manifest.scope.tool,'--stream',manifest.scope.stream,'--revision',manifest.revision]


def test_cli_import_defaults_incomplete(tmp_path,capsys):
    _, manifest, _ = fixture()
    assert main(arguments(tmp_path,manifest)) == 0
    result=json.loads(capsys.readouterr().out)
    assert result['occurrences']==1 and result['complete'] is False


def test_cli_explicit_complete_and_mismatch(tmp_path,capsys):
    _, manifest, _=fixture()
    args=arguments(tmp_path,manifest)
    assert main(args+['--complete','--checked-category','drc'])==0
    assert json.loads(capsys.readouterr().out)['complete'] is True
    args[-1]='wrong-revision'
    assert main(args)==2
    assert 'rejected' in capsys.readouterr().err


def test_cli_missing_report_and_size_bound(tmp_path,capsys):
    _, manifest, _=fixture();args=arguments(tmp_path,manifest)
    (tmp_path/'report.json').unlink()
    assert main(args)==2 and 'rejected' in capsys.readouterr().err
    p=tmp_path/'oversize';p.write_bytes(b'abcdef')
    import pytest
    with pytest.raises(ValueError,match='limit'):read(p,maximum=5)


def test_cli_extract_without_overwriting_reviewed_evidence(tmp_path,monkeypatch,capsys):
    _, manifest, content=fixture()
    from openwaiver import physical_native
    monkeypatch.setattr(physical_native,'extract_layout',lambda **kw:manifest)
    report=tmp_path/'report.json';report.write_text(content)
    output=tmp_path/'manifest.json'
    args=['extract','--layout',str(tmp_path/'layout.gds'),'--top','TOP','--layer','1/0','--halo-dbu','500',
          '--report',str(report),'--format','json','--output',str(output),'--project',manifest.scope.project,
          '--tool',manifest.scope.tool,'--stream',manifest.scope.stream,'--revision',manifest.revision]
    assert main(args)==0
    assert json.loads(capsys.readouterr().out)['complete_run_inferred'] is False
    original=output.read_bytes()
    assert main(args)==2 and output.read_bytes()==original
