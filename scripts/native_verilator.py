#!/usr/bin/env python3
"""Execute a narrow, real Verilator importer/exporter round-trip on synthetic RTL.

This validates only the installed executable and fixture, not all Verilator versions
or any proprietary adapter. A native control file remains a lossy derivative.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from openwaiver.exporters import export_report
from openwaiver.importers import parse_report
from openwaiver.models import Principal, Scope
from openwaiver.service import Service
from openwaiver.store import Store


def main():
    executable = shutil.which("verilator")
    if not executable:
        raise RuntimeError("Verilator is required; this conformance check must not be silently skipped")
    version = subprocess.check_output([executable, "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="openwaiver-native-") as directory:
        root = Path(directory)
        source = root / "top.sv"
        # Avoid Verilator's default *unused* name exemption: these must produce diagnostics.
        source.write_text("module top(output wire y);\n  wire unconsumed_a;\n  wire unconsumed_b;\n  assign y = 1'b0;\nendmodule\n")
        def execute(extra=()):
            proc = subprocess.run([executable, "--lint-only", "--Wall", "-Wno-fatal", "--top-module", "top", *extra, "top.sv"],
                                  cwd=root, text=True, capture_output=True, timeout=60)
            if proc.returncode:
                raise AssertionError(f"native run failed: {proc.stdout}\n{proc.stderr}")
            return proc.stdout + proc.stderr
        baseline = execute()
        service = Service(Store(root / "workspace.sqlite3"))
        owner = Principal(name="engineer", role="contributor")
        reviewer = Principal(name="reviewer", role="reviewer")
        scope = Scope(project="synthetic-conformance", stream="lint", tool="verilator")
        run = service.import_run(owner, content=baseline, format="verilator", scope=scope,
            revision="fixture-A", complete=True, checked_categories=["lint"], tool_version=version, source_root=root)
        assert len(run.violations) == 2, baseline
        target = next(v for v in run.violations if v.line == 2)
        w = service.propose(owner, run_id=run.id, violation_id=target.id,
            rationale="Synthetic fixture exception bounded to this exact source revision.",
            owner=owner.name, reviewers=[reviewer.name], valid_revision=run.revision)
        w = service.attach(owner, w.id, w.version, "fixture-evidence.txt", b"Synthetic conformance evidence only.")
        w = service.submit(owner, w.id, w.version)
        service.review(reviewer, w.id, w.version, "approve", "Independent synthetic fixture approval.")
        assessment = service.assessment(run.id)
        controls = export_report(assessment, "verilator", acknowledge_lossy=True)
        (root / "waivers.vlt").write_text(controls)
        filtered = parse_report(execute(["waivers.vlt"]), "verilator")
        assert len(filtered) == 1 and filtered[0].line == 3, "native export suppressed the wrong occurrence"
        # A new source revision never inherits a revision-bound native waiver in our ledger.
        source.write_text(source.read_text() + "// changed design revision\n")
        changed = service.import_run(owner, content=execute(), format="verilator", scope=scope,
            revision="fixture-B", complete=True, checked_categories=["lint"], tool_version=version, source_root=root)
        changed_result = service.assessment(changed.id)
        assert changed_result["counts"].get("waived", 0) == 0 and not changed_result["gate_pass"]
    result = {"tool_version": version, "passed": True, "synthetic_only": True,
              "checks": ["native unfiltered diagnostics imported", "approved derivative accepted by native executable",
                         "unapproved sibling diagnostic remains", "changed revision blocked"],
              "qualification_scope": "Only this executable version and synthetic fixture; not vendor-wide qualification."}
    output = ROOT / "validation-results" / "native-verilator.json"
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
