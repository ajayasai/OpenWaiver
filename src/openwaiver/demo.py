"""Synthetic reference chip, with actual backend workflows (not hardcoded assessment results)."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path

from .models import Principal, Scope, utcnow
from .service import Service
from .store import Store


def seed(path: Path) -> dict:
    if path.exists():
        raise ValueError("demo database already exists; use a new directory to avoid overwriting work")
    service = Service(Store(path))
    owner = Principal(name="engineer", role="contributor")
    review1 = Principal(name="reviewer", role="reviewer")
    review2 = Principal(name="signoff", role="reviewer")
    scope = Scope(project="Orion reference SoC", stream="nightly-reference", tool="synthetic-eda")
    context = hashlib.sha256(b"synthetic context v1").hexdigest()
    rows = []
    descriptions = [
        ("drc", "M2.SPACING", "Metal 2 minimum spacing below the local rule threshold", "top/serdes"),
        ("drc", "VIA.ENCLOSURE", "Via enclosure marker at macro boundary", "top/sram"),
        ("cdc", "CDC.SYNC", "Cross-domain signal has a reviewed synchronization path", "top/usb"),
        ("lint", "UNUSEDSIGNAL", "Debug-only signal is not consumed in this configuration", "top/debug"),
        ("erc", "ERC.FLOAT", "Unconnected test-mode pad in production assembly", "top/io"),
        ("low_power", "UPF.ISO", "Isolation rule requires power-intent review", "top/npu"),
        ("coverage", "COV.UNREACH", "Safety fallback branch is unreachable in normal operation", "top/safety"),
        ("timing", "STA.EXCEPTION", "Test clock timing exception requires signoff", "top/clock"),
        ("lvs", "LVS.PIN", "Macro pin equivalence requires schematic evidence", "top/pll"),
        ("rdc", "RDC.RESET", "Reset release crosses the subsystem boundary", "top/media"),
    ]
    for i, (cat, rule, message, hier) in enumerate(descriptions):
        v = {"id": f"finding-{i + 1}", "category": cat, "rule": rule, "message": message,
             "severity": "warning" if cat in ("lint", "coverage") else "error", "hierarchy": hier,
             "path": f"rtl/{hier.split('/')[-1]}.sv", "line": 40 + i * 7, "context_hash": context}
        if cat in ("drc", "lvs", "erc"):
            v["geometries"] = [{"kind": "box", "points": [[10 + i * 5, 20], [13 + i * 5, 23]],
                                "unit": "um", "layer": "M2"}]
        rows.append(v)
    cats = list(dict.fromkeys(v["category"] for v in rows))
    def run(values, rev):
        return service.import_run(owner, content=json.dumps({"schema_version": 1, "violations": values}),
            format="json", scope=scope, revision=rev, complete=True, checked_categories=cats,
            tool_version="reference-1", configuration_digest=hashlib.sha256(b"reference-config").hexdigest())
    baseline = run(rows, "candidate-A")
    waivers = []
    for i in range(8):
        reviewers = ["reviewer", "signoff"] if rows[i]["category"] in ("cdc", "rdc", "timing") else ["reviewer"]
        w = service.propose(owner, run_id=baseline.id, violation_id=rows[i]["id"],
            rationale="SYNTHETIC DEMO: reviewed reference exception; replace with real engineering evidence.",
            owner="engineer", reviewers=reviewers, expires_on=utcnow().date() + timedelta(days=30),
            tags=["reference", "not-real-design-data"])
        w = service.attach(owner, w.id, w.version, "review-evidence.txt",
                           f"Synthetic evidence for {rows[i]['rule']}; not a real signoff record.".encode())
        if i != 7:
            w = service.submit(owner, w.id, w.version)
        if i not in (5, 7):
            w = service.review(review1, w.id, w.version, "approve", "Synthetic independent review for demo only.")
            if len(reviewers) == 2:
                w = service.review(review2, w.id, w.version, "approve", "Synthetic second reviewer concurrence.")
        waivers.append(w)
    snap_a = service.freeze(review1, baseline.id, "Candidate A · reference baseline")
    current = json.loads(json.dumps(rows))
    current[0]["geometries"][0]["points"] = [[11, 20], [14, 23]]
    current[1]["geometries"][0]["points"] = [[15, 20], [19, 24]]
    current[3]["context_hash"] = hashlib.sha256(b"changed surrounding RTL").hexdigest()
    current = [v for v in current if v["id"] != "finding-7"]  # unused coverage waiver, complete run
    current.append({"id": "finding-11", "category": "drc", "rule": "M1.WIDTH", "severity": "error",
                    "message": "New metal width violation requires investigation", "hierarchy": "top/cpu",
                    "geometries": [{"kind": "box", "points": [[80, 20], [80.2, 24]], "layer": "M1"}]})
    candidate = run(current, "candidate-B")
    snap_b = service.freeze(review1, candidate.id, "Candidate B · changed design")
    return {"database": str(path), "baseline_run": baseline.id, "current_run": candidate.id,
            "snapshots": [snap_a.id, snap_b.id], "waivers": [w.id for w in waivers]}
