import pytest
from openwaiver.exporters import export_report
from openwaiver.errors import OpenWaiverError


def test_native_export_cannot_suppress_unapproved_same_line(service, make_run, make_waiver, record):
    make_waiver(make_run())
    run = make_run([record, {**record, "id": "sibling", "column": 17,
                            "message": "A different unreviewed occurrence on the same line"}])
    result = service.assessment(run.id)
    assert result["counts"].get("waived") == 1
    with pytest.raises(OpenWaiverError, match="also suppress"):
        export_report(result, "verilator", acknowledge_lossy=True)


def test_preflight_keeps_distinct_lines_exportable(service, make_run, make_waiver, record):
    make_waiver(make_run())
    run = make_run([record, {**record, "id": "sibling", "line": 101,
                            "message": "Another occurrence on a different line"}])
    result = export_report(service.assessment(run.id), "verilator", acknowledge_lossy=True)
    assert "-lines 21" in result and "-lines 101" not in result
