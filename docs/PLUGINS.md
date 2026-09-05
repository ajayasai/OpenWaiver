# Adapter SDK

Built-in adapters cover documented neutral formats plus explicit native subsets. New adapters must be small, strict, version-aware and regression-tested against legally redistributable fixtures. Do not reverse engineer encrypted or access-controlled foundry data as part of this project.

Register importers/exporters using Python entry points in your separately installed package:

```toml
[project.entry-points."openwaiver.importers"]
my_documented_format = "my_adapter:parse"

[project.entry-points."openwaiver.exporters"]
my_control_format = "my_adapter:export"
```

The importer receives a UTF-8 string and must return a list of `openwaiver.models.Violation` instances. The core checks output cardinality, validates records and assigns missing IDs. Reject anything you cannot interpret completely. Preserve source identifiers, hierarchy, coordinates, units, coordinate frames, multiplicity, context and tool provenance where available. Never infer approval from a native suppressed flag.

```python
from openwaiver.models import Violation
from openwaiver.importers import canonical_json

def parse(text: str) -> list[Violation]:
    # Replace with a strict, documented, version-checked parser.
    return canonical_json(text)

def export(assessment: dict) -> str:
    # A safe demonstration exporter, not a native waiver syntax.
    rows = [r for r in assessment["violations"] if r["status"] == "waived"]
    return "\n".join(r["fingerprint"] for r in rows) + "\n"
```

Enable trusted installed adapters explicitly with CLI `--allow-plugins`. The API does not accept arbitrary plug-in names with execution enabled. Plug-ins are local executable Python and are not sandboxed. The hook signature has no implicit credentials, subprocess invocation or file-system root.

For a native waiver exporter, demonstrate that exported scope is no broader than approved identity. When the vendor format cannot express that, require deliberate acknowledgment and document all lost constraints. Re-run a raw/unfiltered check before regenerating derivatives. A report filtered by your own output is not independent evidence that a violation disappeared.

Required adapter tests: clean file, realistic finding, unknown record, truncated/malformed input, duplicate occurrences, unsafe native metacharacters, unresolved hierarchy/multiplicity, changed coordinates/message/context, cross-project isolation and no promotion of imported suppressions to approvals. Include vendor/tool version and authoritative format documentation. Native compatibility claims require execution against that tool release, not just matching a sample string.
