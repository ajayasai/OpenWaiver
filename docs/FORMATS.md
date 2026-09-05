# Input formats

All importers preserve duplicate occurrences and assign run-local IDs where needed. All reports are UTF-8 and bounded to 32 MiB / 250,000 findings. The application does not read proprietary binary EDA databases. Native-format support is a documented subset, not automatic compatibility with every tool release.

## Canonical JSON

```json
{
  "schema_version": 1,
  "violations": [{
    "id": "v-1", "category": "lint", "rule": "WIDTH", "severity": "warning",
    "message": "Signal has width 32, expected 16",
    "hierarchy": "top/u1", "path": "rtl/top.sv", "line": 21, "column": 2,
    "object_id": "", "context_hash": "", "geometries": [], "multiplicity": 1,
    "metadata": {}
  }]
}
```

Categories: `drc`, `lvs`, `erc`, `lint`, `cdc`, `rdc`, `low_power`, `coverage`, `timing`. Severities: `info`, `warning`, `error`, `critical`. A finding requires a rule, a nonblank message and at least one location/identity anchor. Line/column are positive; a line requires a path and a column requires a line. Context hashes, when present, are lowercase SHA-256 hex. Unknown fields, duplicate JSON keys, nonfinite coordinates and duplicate explicit IDs are rejected.

Geometry example:

```json
{"kind":"polygon","points":[[0,0],[10,0],[10,2],[0,2]],"unit":"um","layer":"M2","frame":"top"}
```

Supported kinds: point (1 point), edge/box (2), polygon (at least 3). Units `um`, `nm`, `dbu` remain explicit and are never implicitly converted. Use a documented frame and resolved instance identifier for hierarchical geometry; the importer cannot infer physical transforms.

Run provenance is supplied separately: `project`, `stream`, `tool`, `revision`, `tool_version`, `rule_deck_digest`, `configuration_digest`, `complete`, `checked_categories`. Complete runs must list every imported category. Empty complete reports still require an explicit category coverage declaration.

## CSV, XML and text

CSV uses canonical field names; `category`, `rule`, `message` are mandatory headers. Geometries and metadata use JSON in their cells. Quotes follow ordinary CSV escaping. Duplicate/unknown columns and ragged rows fail.

XML uses `<violations schema_version="1">` containing `<violation>` elements with canonical fields as direct children. Geometry/metadata values contain JSON text. Nested ad hoc structures, unknown fields and duplicate children fail. XML external entities are forbidden. This format is **not** the schema of an arbitrary vendor's report.

Text uses exactly eight pipe-separated, CSV-quoted fields per nonblank/non-comment line:

```
category|severity|rule|hierarchy|path|line|column|message
lint|warning|WIDTH|top/u1|rtl/top.sv|21|2|Signal has width 32, expected 16
```

The first explanatory line above is the grammar, **not a header to include**. Blank and `#` comment lines are ignored; all other lines must conform. Empty line/column cells are allowed for non-source findings. Unsupported lines do not disappear silently.

## Verilator diagnostics

Recognizes `%Warning-RULE:` and `%Error-RULE:` source-located diagnostics with line and column, indented continuation context and the known exit summary. Unknown unindented text and uncoded errors fail import. This is a fixture-tested textual subset; banner/version differences may require adapter updates. The format enforces the `verilator` tool namespace. A nonempty summary-only log is not treated as a clean report.

Authoritative syntax reference: https://verilator.org/guide/latest/control.html

## SARIF 2.1.0

Supports one tool run, text messages, direct resolved artifact URIs and at most one primary location. Rejects failed invocations, unresolved base/index locations and unsupported multiple locations. The namespace must match the driver name. Existing suppressions are imported as untrusted metadata, never approved waivers. It is not a lossless implementation of the entire SARIF schema or every extension. OpenWaiver SARIF export provides results, status, fingerprints and external accepted suppression only for actually effective waivers.

Standard schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json

## KLayout report database

Supports `<report-database><items><item>…` with category, cell, multiplicity and values. Supported values: box, polygon, edge, point, text, integer and float. Multiple geometries, cell variants, comments and incoming tags are retained. Incoming `waived` tags are untrusted, not lifecycle approvals. Coordinates are represented as local-cell micrometers, consistent with the documented report database. Aggregated instances cannot be waived automatically. Edge pairs, polygons with holes and unrecognized value types fail rather than being approximated.

Format reference: https://www.klayout.de/rdb_format.html

The reference fixtures are independently written synthetic examples. Native KLayout/Verilator executable round-trip qualification is not included in the local validation unless explicitly recorded in `VALIDATION.md`.
