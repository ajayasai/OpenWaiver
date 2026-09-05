"""Offline evidence, explicit dependency manifests and Git plan commands."""
from __future__ import annotations

from datetime import date
import json
from pathlib import Path
import yaml

from .errors import OpenWaiverError
from .importers import strict_json
from .interchange import load_yaml
from .models import Principal
from .service import Service
from .store import Store

COMMANDS = {"context-build", "context-compare", "plan-template", "plan-preview", "plan-apply",
            "keygen", "sign-file", "verify-file", "checkpoint", "verify-checkpoint", "verify-evidence"}


def add_parsers(sub):
    p = sub.add_parser("context-build", help="hash explicit dependency files in an immutable workspace")
    p.add_argument("specification")
    p.add_argument("--root", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("context-compare", help="explain the exact targets affected by dependency changes")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--output")
    p = sub.add_parser("plan-template", help="create a reviewable proposal plan for explicitly selected findings")
    p.add_argument("run")
    p.add_argument("--violation", action="append", required=True, dest="violations")
    p.add_argument("--rationale", required=True)
    p.add_argument("--reviewers", required=True)
    p.add_argument("--expires", type=date.fromisoformat)
    p.add_argument("--valid-revision")
    p.add_argument("--output", required=True)
    for command in ("plan-preview", "plan-apply"):
        p = sub.add_parser(command, help="preview or atomically apply a proposal-only YAML change plan")
        p.add_argument("file")
        p.add_argument("--output")
        if command == "plan-apply":
            p.add_argument("--expected-digest", required=True)
    p = sub.add_parser("keygen", help="create an offline Ed25519 keypair without overwriting files")
    p.add_argument("--private-key", required=True)
    p.add_argument("--public-key", required=True)
    for command in ("sign-file", "checkpoint"):
        p = sub.add_parser(command, help="sign artifact bytes or a verified audit checkpoint offline")
        if command == "sign-file":
            p.add_argument("file")
        p.add_argument("--private-key", required=True)
        p.add_argument("--subject", required=True)
        p.add_argument("--hours", type=float, default=24)
        p.add_argument("--output", required=True)
    for command in ("verify-file", "verify-checkpoint", "verify-evidence"):
        p = sub.add_parser(command, help="verify against an independently distributed Ed25519 public key")
        if command != "verify-checkpoint":
            p.add_argument("file")
        required = command != "verify-evidence"
        p.add_argument("--signature", required=required)
        p.add_argument("--public-key", required=required)
        p.add_argument("--subject", required=required)
        if command == "verify-checkpoint":
            p.add_argument("--minimum-sequence", type=int, default=0)
        p.add_argument("--output")


def read(path: str, limit: int = 4 * 1024 * 1024) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise OpenWaiverError("input file exceeds operation size limit")
    return data


def write_new(path: str, content: str):
    # Do not silently replace reviewed plans, signing keys, or signed evidence.
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(content)


def run_extension(args) -> int | None:
    command = args.command
    if command not in COMMANDS:
        return None
    if command in ("context-build", "context-compare"):
        from .context import ContextManifest, build_context, compare_context
        if command == "context-build":
            result = build_context(Path(args.root), load_yaml(read(args.specification).decode())).model_dump(mode="json")
        else:
            before = ContextManifest.model_validate(load_yaml(read(args.before).decode()))
            after = ContextManifest.model_validate(load_yaml(read(args.after).decode()))
            result = compare_context(before, after)
    elif command.startswith("plan-"):
        from .plans import ReviewPlan, apply_plan, preview_plan, proposal_template
        service = Service(Store(args.db))
        actor = Principal(name=args.actor, role=args.role)
        if command == "plan-template":
            plan = proposal_template(service, actor, args.run, args.violations, args.rationale,
                                     args.reviewers.split(","), args.expires, args.valid_revision)
            write_new(args.output, yaml.safe_dump(plan.model_dump(mode="json"), sort_keys=False))
            print(json.dumps({"output": args.output, "operations": len(plan.operations), "approvals_granted": 0}))
            return 0
        plan = ReviewPlan.model_validate(load_yaml(read(args.file).decode()))
        result = (preview_plan(service, actor, plan) if command == "plan-preview"
                  else apply_plan(service, actor, plan, args.expected_digest))
    else:
        from .attestation import (Attestation, checkpoint, generate_keypair, load_private, load_public,
                                  sign_file, verify_checkpoint, verify_file)
        if command == "keygen":
            result = generate_keypair(Path(args.private_key), Path(args.public_key))
        elif command in ("sign-file", "checkpoint"):
            key = load_private(Path(args.private_key))
            signed = (sign_file(read(args.file, 256 * 1024 * 1024), key, args.subject, args.hours)
                      if command == "sign-file" else checkpoint(Store(args.db), key, args.subject, args.hours))
            result = signed.model_dump(mode="json")
        else:
            data = read(args.file, 256 * 1024 * 1024) if command != "verify-checkpoint" else None
            if command == "verify-evidence":
                from .evidence import verify_evidence
                result = verify_evidence(data)
                if any((args.signature, args.public_key, args.subject)) and not all((args.signature, args.public_key, args.subject)):
                    raise OpenWaiverError("signed verification requires signature, public key AND expected subject")
                if not args.signature:
                    return emit(result, args)
            envelope = Attestation.model_validate(strict_json(read(args.signature).decode()))
            key = load_public(Path(args.public_key))
            if command == "verify-checkpoint":
                result = verify_checkpoint(Store(args.db), envelope, key, args.subject, args.minimum_sequence)
            else:
                verified = verify_file(data, envelope, key, args.subject)
                result = {**result, **verified, "externally_anchored": True} if command == "verify-evidence" else verified
    return emit(result, args)


def emit(result, args):
    content = json.dumps(result, indent=2) + "\n"
    output = getattr(args, "output", None)
    if output:
        write_new(output, content)
        print(json.dumps({"output": output}))
    else:
        print(content, end="")
    return 0
