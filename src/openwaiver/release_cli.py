"""Operator CLI for receipt-gated release contracts and independently replayable capsules."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .assurance import ReleaseContract, capture_inventory, evaluate_contract
from .attestation import load_private
from .capsule import MAX_CAPSULE_BYTES, seal_capsule, verify_capsule
from .execution import ExecutionClaim, ExecutionReceipt, read_trust, sign_execution
from .identity import canonical, digest
from .importers import strict_json
from .interchange import load_yaml
from .service import Service
from .store import Store


def read_bytes(path, maximum=32 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input byte budget exceeded")
    return data


def read_document(path):
    text = read_bytes(path).decode("utf-8-sig")
    return load_yaml(text) if Path(path).suffix.lower() in (".yaml", ".yml") else strict_json(text)


def write_new(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    template = sub.add_parser("template", help="draft a fully pinned contract; does not authorize it")
    template.add_argument("--db", required=True)
    template.add_argument("--project", required=True)
    template.add_argument("--revision", required=True)
    template.add_argument("--run-id", action="append", required=True)
    template.add_argument("--design-sha256", required=True)
    template.add_argument("--max-waived", type=int, default=0)
    template.add_argument("--output", required=True)
    attest = sub.add_parser("attest", help="sign explicit producer metadata bound to an audited imported run")
    attest.add_argument("--db", required=True)
    attest.add_argument("--run-id", required=True)
    attest.add_argument("--metadata", required=True, help="execution times, status, design/invocation/stdout/stderr SHA-256")
    attest.add_argument("--key", required=True)
    attest.add_argument("--hours", type=float, default=24)
    attest.add_argument("--output", required=True)
    gate = sub.add_parser("gate", help="evaluate receipts, provenance, reviews and risk budget")
    seal = sub.add_parser("seal", help="freeze selected evidence in one transaction and sign a capsule")
    verify = sub.add_parser("verify", help="offline signature and policy replay; requires independent contract and trust")
    for command in (gate, seal, verify):
        command.add_argument("--contract", required=True)
        command.add_argument("--trust", required=True)
    for command in (gate, seal):
        command.add_argument("--db", required=True)
        command.add_argument("--receipt", action="append", default=[])
    seal.add_argument("--key", required=True)
    seal.add_argument("--hours", type=float, default=24)
    seal.add_argument("--output", required=True)
    seal.add_argument("--diagnostic", action="store_true", help="explicitly allow sealing a BLOCKED result")
    verify.add_argument("--capsule", required=True)
    verify.add_argument("--db", help="also reconcile the frozen inventory against current audited state")
    args = parser.parse_args(argv)
    try:
        if args.command == "template":
            service = Service(Store(args.db))
            with service.store.transaction(write=False) as conn:
                service.store.verify(conn)
                runs = [service.store.get(conn, "runs", rid) for rid in args.run_id]
                if any(r.scope.project != args.project or r.revision != args.revision for r in runs):
                    raise ValueError("all selected runs must belong to this project and revision")
                checks = [dict(stream=r.scope.stream, tool=r.scope.tool, categories=r.checked_categories,
                               run_id=r.id, tool_version=r.tool_version, rule_deck_digest=r.rule_deck_digest,
                               configuration_digest=r.configuration_digest) for r in runs]
                contract = ReleaseContract(manifest=dict(project=args.project, revision=args.revision, checks=checks),
                    policy_sha256=digest(service.store.policy(conn)), design_sha256=args.design_sha256,
                    budget=dict(max_waived_findings=args.max_waived))
            write_new(args.output, (canonical(contract) + "\n").encode())
            result = {"contract_sha256": digest(contract), "path": args.output, "authorized": False,
                      "next_step": "Review the contract, then independently provision its digest in trust.approved_contracts."}
        elif args.command == "attest":
            service = Service(Store(args.db))
            with service.store.transaction(write=False) as conn:
                service.store.verify(conn)
                run = service.store.get(conn, "runs", args.run_id)
            metadata = read_document(args.metadata)
            if not isinstance(metadata, dict) or {"run_id", "run_sha256"} & metadata.keys():
                raise ValueError("metadata must not override the database-selected run binding")
            claim = ExecutionClaim(run_id=run.id, run_sha256=digest(run), **metadata)
            if claim.finished_at > run.created_at:
                raise ValueError("execution must finish before import")
            receipt = sign_execution(claim, load_private(Path(args.key)), hours=args.hours)
            write_new(args.output, (canonical(receipt) + "\n").encode())
            result = {"run_id": run.id, "receipt_sha256": digest(receipt), "path": args.output,
                      "notice": "The producer is responsible for truthful metadata and complete unfiltered collection."}
        else:
            contract = ReleaseContract.model_validate(read_document(args.contract))
            trust = read_trust(Path(args.trust))
            if args.command == "verify":
                result = verify_capsule(read_bytes(args.capsule, MAX_CAPSULE_BYTES), contract, trust,
                                        service=Service(Store(args.db)) if args.db else None)
                print(json.dumps(result, indent=2))
                accepted = result["release_usable_now"] if args.db else result["frozen_state_gate_pass_now"]
                return 0 if accepted else 1
            receipts = [ExecutionReceipt.model_validate(read_document(path)) for path in args.receipt]
            service = Service(Store(args.db))
            if args.command == "gate":
                result = evaluate_contract(contract, **capture_inventory(service, contract), receipts=receipts, trust=trust)
                print(json.dumps(result, indent=2))
                return 0 if result["gate_pass"] else 1
            data = seal_capsule(service, contract, receipts, trust, load_private(Path(args.key)),
                                hours=args.hours, allow_blocked=args.diagnostic)
            write_new(args.output, data)
            result = {"path": args.output, "bytes": len(data), "contract_sha256": digest(contract),
                      "diagnostic_allowed": args.diagnostic, "notice": "Verify against independent contract and trust before use."}
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        print(f"release assurance rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
