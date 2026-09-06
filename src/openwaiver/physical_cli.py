"""Explicit local operator commands for physical evidence. No remote file reads."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from .identity import canonical
from .importers import MAX_REPORT_BYTES, strict_json
from .models import Principal, Scope
from .physical import PhysicalManifest


def read(path, maximum=MAX_REPORT_BYTES):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input byte limit exceeded")
    return data.decode("utf-8-sig")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    extract = sub.add_parser("extract", help="derive exact neighborhoods from GDS/OASIS")
    extract.add_argument("--layout", required=True)
    extract.add_argument("--top", required=True)
    extract.add_argument("--layer", action="append", required=True)
    extract.add_argument("--halo-dbu", type=int, required=True)
    extract.add_argument("--placements", help="JSON map of occurrence IDs to actual placement selectors")
    extract.add_argument("--output", required=True)
    ingest = sub.add_parser("import", help="import a report with retained, validated physical evidence")
    ingest.add_argument("--manifest", required=True)
    ingest.add_argument("--db", required=True)
    ingest.add_argument("--actor", required=True)
    ingest.add_argument("--complete", action="store_true", help="assert the underlying EDA run was complete and unfiltered")
    ingest.add_argument("--checked-category", action="append", default=[])
    ingest.add_argument("--tool-version", default="")
    ingest.add_argument("--rule-deck-digest", default="")
    ingest.add_argument("--configuration-digest", default="")
    for cmd in (extract, ingest):
        cmd.add_argument("--report", required=True)
        cmd.add_argument("--format", choices=["json", "klayout", "xml", "csv"], required=True)
        for field in ("project", "stream", "tool", "revision"):
            cmd.add_argument("--" + field, required=True)
    args = p.parse_args(argv)
    try:
        scope = Scope(project=args.project, stream=args.stream, tool=args.tool)
        content = read(args.report)
        if args.command == "extract":
            from .physical_native import extract_layout
            manifest = extract_layout(layout_path=Path(args.layout), content=content, format=args.format,
                scope=scope, revision=args.revision, top_cell=args.top, layers=args.layer, halo_dbu=args.halo_dbu,
                placements=strict_json(read(args.placements)) if args.placements else None)
            # Never overwrite previously approved evidence accidentally.
            with Path(args.output).open("x", encoding="utf-8") as out:
                out.write(canonical(manifest) + "\n")
            result = {"path": args.output, "occurrences": len(manifest.targets), "complete_run_inferred": False}
        else:
            from .service import Service
            from .store import Store
            manifest = PhysicalManifest.model_validate(strict_json(read(args.manifest)))
            service = Service(Store(args.db))
            run = service.import_run(Principal(name=args.actor, role="contributor"), content=content,
                format=args.format, scope=scope, revision=args.revision, complete=args.complete,
                checked_categories=args.checked_category, tool_version=args.tool_version,
                rule_deck_digest=args.rule_deck_digest, configuration_digest=args.configuration_digest,
                physical_manifest=manifest.model_dump(mode="json"))
            result = {"run_id": run.id, "occurrences": len(run.violations), "complete": run.complete}
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"physical evidence rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
