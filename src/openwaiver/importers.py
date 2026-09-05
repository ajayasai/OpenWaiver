"""Bounded parsers for documented formats; malformed data never becomes a clean run."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.parse import unquote

from defusedxml import ElementTree as ET

from .errors import OpenWaiverError
from .models import Geometry, Violation

MAX_REPORT_BYTES = 32 * 1024 * 1024


def strict_json(data: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise OpenWaiverError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def bad_constant(s):
        raise OpenWaiverError(f"non-finite JSON constant: {s}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def canonical_json(data: str) -> list[Violation]:
    doc = strict_json(data)
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "violations"}:
        raise OpenWaiverError("JSON requires exactly schema_version and violations")
    if doc["schema_version"] != 1 or not isinstance(doc["violations"], list):
        raise OpenWaiverError("unsupported JSON schema or non-list violations")
    return [Violation.model_validate(x) for x in doc["violations"]]


def csv_report(data: str) -> list[Violation]:
    reader = csv.DictReader(io.StringIO(data))
    fields = reader.fieldnames or []
    if len(set(fields)) != len(fields) or not {"category", "rule", "message"} <= set(fields):
        raise OpenWaiverError("CSV needs unique headers including category, rule, message")
    if set(fields) - Violation.model_fields.keys():
        raise OpenWaiverError("unknown CSV columns; use the canonical schema or an adapter")
    out = []
    for number, row in enumerate(reader, 2):
        if None in row or any(value is None for value in row.values()):
            raise OpenWaiverError(f"ragged CSV row {number}")
        values = {k: v for k, v in row.items() if v != ""}
        for key in ("geometries", "metadata"):
            if key in values:
                values[key] = strict_json(values[key])
        out.append(Violation.model_validate(values))
    return out


def xml_report(data: str) -> list[Violation]:
    root = ET.fromstring(data)
    if root.tag != "violations" or root.attrib != {"schema_version": "1"}:
        raise OpenWaiverError('XML root must be <violations schema_version="1">')
    out = []
    for element in root:
        if element.tag != "violation" or element.attrib:
            raise OpenWaiverError("unexpected XML element or attributes")
        row = {}
        for child in element:
            if child.tag in row or list(child) or child.attrib:
                raise OpenWaiverError("duplicate or nested XML field")
            row[child.tag] = child.text or ""
        for key in ("geometries", "metadata"):
            if key in row:
                row[key] = strict_json(row[key])
        out.append(Violation.model_validate(row))
    return out


def text_report(data: str) -> list[Violation]:
    """Explicit eight-field pipe format, not a heuristic parser for arbitrary tool logs."""
    rows = csv.reader(io.StringIO(data), delimiter="|", strict=True)
    keys = ("category", "severity", "rule", "hierarchy", "path", "line", "column", "message")
    out = []
    for row in rows:
        if not row or (len(row) == 1 and row[0].startswith("#")):
            continue
        if len(row) != len(keys):
            raise OpenWaiverError("text rows need eight pipe-delimited fields")
        out.append(Violation.model_validate({k: v for k, v in zip(keys, row) if v}))
    return out


_VL = re.compile(r"^%(Warning|Error)(?:-([A-Z0-9_]+))?: (.+?):(\d+):(?:(\d+):)?\s*(.+)$")


def verilator(data: str) -> list[Violation]:
    out = []
    for line in data.splitlines():
        if not line.strip():
            continue
        match = _VL.match(line)
        if match:
            severity, rule, path, ln, col, message = match.groups()
            if not rule:
                # Uncoded fatal compiler errors must never be disguised as waivable lint.
                raise OpenWaiverError("uncoded Verilator error: repair the tool run before import")
            out.append(Violation(category="lint", severity="warning" if severity == "Warning" else "error",
                                 rule=rule, path=path, line=int(ln), column=int(col) if col else None,
                                 message=message))
        elif re.fullmatch(r"%Error: Exiting due to \d+ warning\(s\)", line):
            if not out:
                raise OpenWaiverError("warning summary without diagnostics")
        elif out and (line.startswith(" ") or line.startswith("\t")):
            # Keep the full message including source excerpts: changes cannot inherit approval.
            out[-1].message += "\n" + line
        elif line.startswith("- Verilator:"):
            continue
        else:
            raise OpenWaiverError(f"unrecognized Verilator line: {line[:160]}")
    if not out and data.strip():
        raise OpenWaiverError("nonempty Verilator report contained no supported diagnostics")
    return out


def sarif(data: str) -> list[Violation]:
    doc = strict_json(data)
    if doc.get("version") != "2.1.0" or len(doc.get("runs", [])) != 1:
        raise OpenWaiverError("import one SARIF 2.1.0 tool run at a time")
    run = doc["runs"][0]
    if "results" not in run or not isinstance(run["results"], list):
        raise OpenWaiverError("SARIF requires an explicit results array; missing data is not a clean run")
    for invocation in run.get("invocations", []):
        if invocation.get("executionSuccessful") is False:
            raise OpenWaiverError("SARIF tool invocation failed")
    out = []
    for item in run.get("results", []):
        props = item.get("properties", {})
        locations = item.get("locations", [])
        if len(locations) > 1:
            raise OpenWaiverError("multi-location SARIF needs an explicit adapter; no locations dropped")
        physical = locations[0].get("physicalLocation", {}) if locations else {}
        artifact = physical.get("artifactLocation", {})
        if "uriBaseId" in artifact or ("index" in artifact and "uri" not in artifact):
            raise OpenWaiverError("resolve SARIF artifact references before import")
        region = physical.get("region", {})
        out.append(Violation(
            category=props.get("category", "lint"), rule=item.get("ruleId", ""),
            severity={"note": "info", "none": "info"}.get(item.get("level", "warning"),
                                                           item.get("level", "warning")),
            message=item.get("message", {}).get("text", ""),
            path=unquote(artifact.get("uri", "")), line=region.get("startLine"),
            column=region.get("startColumn"), hierarchy=props.get("hierarchy", ""),
            object_id=props.get("object_id", ""), context_hash=props.get("context_hash", ""),
            geometries=props.get("geometries", []),
            metadata={"sarif_suppressions_untrusted": item.get("suppressions", []),
                      "sarif_region": region},
        ))
    return out


_NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
_POINT = rf"({_NUMBER})\s*,\s*({_NUMBER})"


def klayout(data: str) -> list[Violation]:
    root = ET.fromstring(data)
    if root.tag != "report-database" or root.find("items") is None:
        raise OpenWaiverError("not a KLayout report-database with items")
    containers = root.findall("items")
    if len(containers) != 1 or any(child.tag != "item" for child in containers[0]):
        raise OpenWaiverError("KLayout requires one items container with only item records")
    out = []
    for item in containers[0]:
        names = [child.tag for child in item]
        known = {"category", "cell", "multiplicity", "tags", "comment", "visited", "image", "values"}
        if len(names) != len(set(names)) or set(names) - known:
            raise OpenWaiverError("unknown or duplicate KLayout item field")
        values = item.find("values")
        if values is not None and any(v.tag != "value" or list(v) or v.attrib for v in values):
            raise OpenWaiverError("unknown or nested KLayout value record")
        geometries = []
        raw_values = [x.text or "" for x in item.findall("./values/value")]
        for value in raw_values:
            kind, sep, coordinates = value.partition(":")
            kind, coordinates = kind.strip(), coordinates.strip()
            if not sep:
                raise OpenWaiverError("malformed KLayout value")
            if kind in ("polygon", "box", "edge", "point"):
                body = coordinates.strip()
                if body.startswith("(") and body.endswith(")"):
                    body = body[1:-1]
                if not re.fullmatch(rf"\s*{_POINT}(?:\s*;\s*{_POINT})*\s*", body):
                    raise OpenWaiverError("unsupported KLayout geometry, including holes or transforms")
                pts = [(float(x), float(y)) for x, y in re.findall(_POINT, body)]
                geometries.append(Geometry(kind=kind, points=pts, unit="um"))
            elif kind not in ("text", "float", "int"):
                raise OpenWaiverError(f"unsupported KLayout value type: {kind}; add a lossless adapter")
        out.append(Violation(
            category="drc", rule=item.findtext("category", ""),
            hierarchy=item.findtext("cell", ""), geometries=geometries,
            message=" | ".join(raw_values) or item.findtext("comment", "DRC marker"),
            multiplicity=int(item.findtext("multiplicity", "1")),
            metadata={"klayout_tags_untrusted": item.findtext("tags", ""),
                      "klayout_comment": item.findtext("comment", "")},
        ))
    return out


PARSERS = {"json": canonical_json, "csv": csv_report, "xml": xml_report,
           "text": text_report, "verilator": verilator, "sarif": sarif, "klayout": klayout}


def parse_report(data: str, format: str, *, allow_plugins: bool = False,
                 source_root: Path | None = None) -> list[Violation]:
    if len(data.encode("utf-8")) > MAX_REPORT_BYTES:
        raise OpenWaiverError("report exceeds 32 MiB limit; split into explicitly partial runs")
    parser = PARSERS.get(format)
    if parser is None and allow_plugins:
        from importlib.metadata import entry_points
        plugins = list(entry_points(group="openwaiver.importers", name=format))
        if len(plugins) == 1:
            parser = plugins[0].load()
    if parser is None:
        raise OpenWaiverError(f"unknown format {format!r}; plug-ins are disabled unless explicitly enabled")
    try:
        results = [Violation.model_validate(x) for x in parser(data)]
        if len(results) > 250000:
            raise OpenWaiverError("too many violations")
        for i, v in enumerate(results):
            if not v.id:
                v.id = f"v{i + 1:07d}"
            if source_root is not None and v.path:
                root = source_root.resolve()
                path = (root / v.path).resolve()
                if not path.is_relative_to(root) or not path.is_file():
                    raise OpenWaiverError("source path missing or outside source_root")
                if path.stat().st_size > MAX_REPORT_BYTES:
                    raise OpenWaiverError("source file exceeds size limit")
                v.context_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if len({v.id for v in results}) != len(results):
            raise OpenWaiverError("duplicate occurrence IDs")
        return results
    except OpenWaiverError:
        raise
    except Exception as exc:
        raise OpenWaiverError(f"invalid {format} report: {type(exc).__name__}: {exc}") from exc
