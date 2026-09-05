"""Interchange and CI reports, plus deliberately narrow native control export."""
from __future__ import annotations

from html import escape
import json
import re
from urllib.parse import quote
import xml.etree.ElementTree as ET

from .errors import OpenWaiverError
from .identity import canonical


def sarif(result: dict) -> str:
    rows = []
    for row in result["violations"]:
        v = row["violation"]
        out = {"ruleId": v["rule"], "level": {"info": "note", "critical": "error"}.get(v["severity"], v["severity"]),
               "message": {"text": v["message"]}, "partialFingerprints": {"openwaiver/v1": row["fingerprint"]},
               "properties": {"openwaiver_status": row["status"], "waiver_ids": row["waiver_ids"],
                              "category": v["category"], "hierarchy": v["hierarchy"],
                              "object_id": v["object_id"], "context_hash": v["context_hash"],
                              "geometries": v["geometries"]}}
        if v["path"]:
            physical = {"artifactLocation": {"uri": quote(v["path"].replace("\\", "/"), safe="/:")}}
            if v["line"]:
                physical["region"] = {"startLine": v["line"]}
                if v["column"]:
                    physical["region"]["startColumn"] = v["column"]
            out["locations"] = [{"physicalLocation": physical}]
        if row["status"] == "waived":
            out["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": "OpenWaiver approval: " + ", ".join(row["waiver_ids"])}]
        rows.append(out)
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": result["scope"]["tool"],
                                                      "informationUri": "https://github.com/ajayasai/OpenWaiver"}},
                                 "results": rows, "properties": {"openwaiver_gate_pass": result["gate_pass"],
                                                                 "complete": result["complete"]}}]}, indent=2)


def junit(result: dict) -> str:
    root = ET.Element("testsuite", name="OpenWaiver policy gate", tests=str(max(1, len(result["blockers"]))),
                      failures=str(len(result["blockers"])))
    if not result["blockers"]:
        ET.SubElement(root, "testcase", name="waiver lifecycle gate")
    for b in result["blockers"]:
        case = ET.SubElement(root, "testcase", name=b.get("violation_id", b["code"]), classname="openwaiver")
        ET.SubElement(case, "failure", type=b["code"], message=b["message"]).text = b["message"]
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def html_report(result: dict) -> str:
    rows = "".join("<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in (
        r["violation"]["category"], r["violation"]["rule"], r["status"],
        r["violation"]["hierarchy"] or r["violation"]["path"], r["violation"]["message"],
        "; ".join(r["reasons"]))) + "</tr>" for r in result["violations"])
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><title>OpenWaiver report</title>"
            "<style>body{font:15px system-ui;margin:3rem;line-height:1.5}table{border-collapse:collapse;width:100%}"
            "td,th{padding:12px;text-align:left;border-bottom:1px solid #ccc;white-space:pre-wrap}"
            "h1{font-size:32px}</style><h1>OpenWaiver · assessment</h1>"
            f"<p>Revision {escape(result['revision'])} · {escape(result['assessed_on'])} · "
            f"Gate: {'PASS' if result['gate_pass'] else 'BLOCKED'}</p>"
            "<p>A waiver is not verification signoff. Approximate matches are never suppressed.</p>"
            "<table><thead><tr><th>Check</th><th>Rule</th><th>Status</th><th>Location</th>"
            "<th>Message</th><th>Reason</th></tr></thead><tbody>" + rows + "</tbody></table></html>")


def verilator(result: dict, *, acknowledge_lossy: bool = False) -> str:
    """Verilator's rule/file/line scope is broader than occurrence identity.

    Refuse by default. Explicit opt-in requires a same-revision UNFILTERED gate run
    BEFORE applying this derivative control file. Never treat the file as durable approval.
    """
    if result["scope"]["tool"].lower() != "verilator":
        raise OpenWaiverError("Verilator export requires a Verilator tool namespace")
    if not acknowledge_lossy:
        raise OpenWaiverError("native file/rule/line controls are lossy; explicit acknowledge_lossy required")
    if not result["complete"]:
        raise OpenWaiverError("native export requires a complete unfiltered source run")
    lines = ["`verilator_config", "// GENERATED DERIVATIVE; not an approval ledger.",
             "// Regenerate after an UNFILTERED OpenWaiver gate for this exact revision.",
             "// File/rule/line cannot enforce context, expiry, hierarchy or message identity."]
    for row in result["violations"]:
        if row["status"] != "waived":
            continue
        v = row["violation"]
        if v["category"] != "lint" or not v["path"] or not v["line"]:
            raise OpenWaiverError("Verilator export requires source-located lint")
        if not re.fullmatch(r"[A-Z0-9_]+", v["rule"]):
            raise OpenWaiverError("unsafe Verilator rule identifier")
        # Do not attempt to escape wildcard semantics or preprocessor directives.
        if not re.fullmatch(r"[A-Za-z0-9_./:+ -]+", v["path"]):
            raise OpenWaiverError("unsafe or wildcard source path for native export")
        lines.append(f'lint_off -rule {v["rule"]} -file "{v["path"]}" -lines {v["line"]}')
    return "\n".join(lines) + "\n"


def export_report(result: dict, format: str, *, acknowledge_lossy: bool = False,
                  allow_plugins: bool = False) -> str:
    functions = {"json": lambda x: json.dumps(x, indent=2), "sarif": sarif,
                 "junit": junit, "html": html_report}
    if format == "verilator":
        return verilator(result, acknowledge_lossy=acknowledge_lossy)
    if format in functions:
        return functions[format](result)
    if allow_plugins:
        from importlib.metadata import entry_points
        plugins = list(entry_points(group="openwaiver.exporters", name=format))
        if len(plugins) == 1:
            value = plugins[0].load()(json.loads(canonical(result)))
            if not isinstance(value, str):
                raise OpenWaiverError("export plug-in must return UTF-8 text")
            return value
    raise OpenWaiverError("unsupported exporter; proprietary formats require a validated adapter")
