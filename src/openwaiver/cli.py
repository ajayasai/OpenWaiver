"""Command-line interface for trusted local operators and CI.

CLI actor/role fields are attribution, not authentication against a hostile local user.
Use the API's token registry for independently authenticated human reviewers.
"""
from __future__ import annotations

import argparse
from datetime import date
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys

from . import __version__
from .engine import compare_snapshots
from .errors import OpenWaiverError
from .exporters import export_report
from .importers import strict_json
from .interchange import bundle, git_export, import_yaml_proposal, load_yaml, verify_bundle
from .models import Policy, Principal, Scope
from .service import Service
from .store import Store


def write_auth(path: Path, name: str, role: str) -> str:
    Principal(name=name, role=role)
    token = secrets.token_urlsafe(32)
    record = {"name": name, "role": role, "sha256": hashlib.sha256(token.encode()).hexdigest()}
    if path.is_symlink():
        raise OpenWaiverError("refusing a symbolic-link token registry")
    existing = strict_json(path.read_text()) if path.exists() else {"tokens": []}
    existing["tokens"].append(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement keeps a partially written token registry from starting a server.
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(existing, out, indent=2)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, path)
    return token


def parser():
    p = argparse.ArgumentParser(description="OpenWaiver — fail-closed, cross-tool waiver lifecycle")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--db", default="workspace/openwaiver.sqlite3")
    p.add_argument("--actor", default=getpass.getuser(), help="trusted local attribution; API uses authenticated identity")
    p.add_argument("--role", choices=["viewer", "contributor", "reviewer", "admin"], default="contributor")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="initialize a workspace without overwriting existing data")
    s = sub.add_parser("auth-create", help="generate one token; prints plaintext once, stores only its hash")
    s.add_argument("--file", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--auth-role", required=True, choices=["viewer", "contributor", "reviewer", "admin"])
    s = sub.add_parser("serve", help="serve the authenticated web dashboard")
    s.add_argument("--auth-file", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--allow-remote", action="store_true")
    s = sub.add_parser("demo", help="create a synthetic reference workspace")
    s.add_argument("--workspace", default="demo-workspace")
    s.add_argument("--serve", action="store_true")
    s.add_argument("--port", type=int, default=8765)
    s = sub.add_parser("import", help="import an unfiltered documented report")
    s.add_argument("file")
    for name in ("format", "project", "stream", "tool", "revision"):
        s.add_argument(f"--{name}", required=True)
    s.add_argument("--complete", action="store_true")
    s.add_argument("--checked", default="", help="comma-separated full checked categories")
    for name in ("tool-version", "rule-deck-digest", "configuration-digest"):
        s.add_argument(f"--{name}", default="")
    s.add_argument("--source-root")
    s.add_argument("--allow-plugins", action="store_true")
    s = sub.add_parser("list")
    s.add_argument("collection", choices=["runs", "waivers", "snapshots"])
    s = sub.add_parser("propose")
    for name in ("run", "violation", "rationale", "owner", "reviewers"):
        s.add_argument(f"--{name}", required=True)
    s.add_argument("--expires", type=date.fromisoformat)
    s.add_argument("--valid-revision")
    for command in ("submit", "approve", "reject", "revoke", "attach", "amend", "rebind"):
        s = sub.add_parser(command)
        s.add_argument("waiver")
        s.add_argument("--version", type=int, required=True)
        if command in ("approve", "reject", "revoke"):
            s.add_argument("--comment", required=True)
        if command == "attach":
            s.add_argument("file")
        if command == "amend":
            s.add_argument("--changes", required=True, help="JSON object; approvals reset")
        if command == "rebind":
            s.add_argument("--run", required=True)
            s.add_argument("--violation", required=True)
    for command in ("assess", "gate", "export"):
        s = sub.add_parser(command)
        s.add_argument("run")
        s.add_argument("--format", default="json")
        s.add_argument("--output")
        s.add_argument("--acknowledge-lossy", action="store_true")
        s.add_argument("--allow-plugins", action="store_true")
    s = sub.add_parser("gate-release", help="gate every required tool stream in an explicit release manifest")
    s.add_argument("manifest")
    s.add_argument("--output")
    s = sub.add_parser("freeze")
    s.add_argument("run")
    s.add_argument("--name", required=True)
    s.add_argument("--require-clean", action="store_true")
    s = sub.add_parser("compare")
    s.add_argument("before")
    s.add_argument("after")
    s = sub.add_parser("export-yaml")
    s.add_argument("destination")
    s = sub.add_parser("import-yaml")
    s.add_argument("file")
    s = sub.add_parser("bundle")
    s.add_argument("snapshot")
    s.add_argument("--output", required=True)
    s.add_argument("--key-file")
    s = sub.add_parser("verify-bundle")
    s.add_argument("file")
    s.add_argument("--key-file")
    s.add_argument("--expected-manifest")
    s = sub.add_parser("audit")
    s.add_argument("--expected-head")
    s = sub.add_parser("policy")
    s.add_argument("--file", help="admin-only policy update from YAML")
    return p


def serve(db, auth_file, host, port, allow_remote=False):
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise OpenWaiverError("remote bind requires --allow-remote, TLS proxy and configured allowed hosts")
    from .api import create_app, token_records
    import uvicorn
    uvicorn.run(create_app(db, token_records(Path(auth_file))), host=host, port=port)


def run(args) -> int:
    command = args.command
    if command == "gate-release":
        from .release import ReleaseManifest, gate_release
        result = gate_release(Store(args.db), ReleaseManifest.model_validate(load_yaml(Path(args.manifest).read_text())))
        content = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(content + "\n", encoding="utf-8")
        else:
            print(content)
        return 0 if result["gate_pass"] else 1
    if command == "auth-create":
        token = write_auth(Path(args.file), args.name, args.auth_role)
        print(f"Token for {args.name} ({args.auth_role}); save it securely:\n{token}")
        return 0
    if command == "serve":
        serve(args.db, args.auth_file, args.host, args.port, args.allow_remote)
        return 0
    if command == "demo":
        from .demo import seed
        workspace = Path(args.workspace)
        result = seed(workspace / "openwaiver.sqlite3")
        auth_file = workspace / "auth.json"
        for name, role in (("engineer", "contributor"), ("reviewer", "reviewer"), ("signoff", "reviewer"), ("observer", "viewer")):
            print(f"{name} token: {write_auth(auth_file, name, role)}", flush=True)
        print(json.dumps(result, indent=2), flush=True)
        print(f"Synthetic data only. Open http://127.0.0.1:{args.port} and use one of these tokens.", flush=True)
        if args.serve:
            serve(result["database"], auth_file, "127.0.0.1", args.port)
        return 0
    if command == "verify-bundle":
        key = Path(args.key_file).read_bytes() if args.key_file else None
        print(json.dumps(verify_bundle(Path(args.file).read_bytes(), key, args.expected_manifest), indent=2))
        return 0
    service = Service(Store(args.db))
    actor = Principal(name=args.actor, role=args.role)
    if command == "init":
        result = {"database": args.db, "version": __version__}
    elif command == "import":
        if Path(args.file).stat().st_size > 32 * 1024 * 1024:
            raise OpenWaiverError("report exceeds 32 MiB")
        result = service.import_run(actor, content=Path(args.file).read_text(encoding="utf-8-sig"),
            format=args.format, scope=Scope(project=args.project, stream=args.stream, tool=args.tool),
            revision=args.revision, complete=args.complete, checked_categories=[x for x in args.checked.split(",") if x],
            tool_version=args.tool_version, rule_deck_digest=args.rule_deck_digest,
            configuration_digest=args.configuration_digest, source_root=Path(args.source_root) if args.source_root else None,
            allow_plugins=args.allow_plugins)
    elif command == "list":
        with service.store.transaction(write=False) as conn:
            result = [x.model_dump(mode="json", exclude={"violations"} if args.collection == "runs" else set())
                      for x in service.store.all(conn, args.collection)]
    elif command == "propose":
        result = service.propose(actor, run_id=args.run, violation_id=args.violation, rationale=args.rationale,
            owner=args.owner, reviewers=args.reviewers.split(","), expires_on=args.expires, valid_revision=args.valid_revision)
    elif command == "submit":
        result = service.submit(actor, args.waiver, args.version)
    elif command in ("approve", "reject"):
        result = service.review(actor, args.waiver, args.version, command, args.comment)
    elif command == "revoke":
        result = service.revoke(actor, args.waiver, args.version, args.comment)
    elif command == "attach":
        path = Path(args.file)
        if path.stat().st_size > 5 * 1024 * 1024:
            raise OpenWaiverError("evidence exceeds 5 MiB")
        result = service.attach(actor, args.waiver, args.version, path.name, path.read_bytes())
    elif command == "amend":
        result = service.amend(actor, args.waiver, args.version, strict_json(args.changes))
    elif command == "rebind":
        result = service.rebind(actor, args.waiver, args.version, args.run, args.violation)
    elif command in ("assess", "gate", "export"):
        result = service.assessment(args.run)
        output = export_report(result, args.format, acknowledge_lossy=args.acknowledge_lossy, allow_plugins=args.allow_plugins)
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(json.dumps({"gate_pass": result["gate_pass"], "counts": result["counts"], "output": args.output}))
        else:
            print(output)
        return 1 if command == "gate" and not result["gate_pass"] else 0
    elif command == "freeze":
        result = service.freeze(actor, args.run, args.name, require_clean=args.require_clean)
    elif command == "compare":
        with service.store.transaction(write=False) as conn:
            service.store.verify(conn)
            result = compare_snapshots(service.store.get(conn, "snapshots", args.before), service.store.get(conn, "snapshots", args.after))
    elif command == "export-yaml":
        result = git_export(service, Path(args.destination))
    elif command == "import-yaml":
        result = import_yaml_proposal(service, actor, Path(args.file).read_text(encoding="utf-8"))
    elif command == "bundle":
        key = Path(args.key_file).read_bytes() if args.key_file else None
        data = bundle(service, args.snapshot, key)
        Path(args.output).write_bytes(data)
        result = {"output": args.output, "bytes": len(data), **verify_bundle(data, key)}
    elif command == "audit":
        with service.store.transaction(write=False) as conn:
            result = service.store.verify(conn, args.expected_head)
    elif command == "policy":
        if args.file:
            result = service.set_policy(actor, Policy.model_validate(load_yaml(Path(args.file).read_text())))
        else:
            with service.store.transaction(write=False) as conn:
                result = service.store.policy(conn)
    else:
        raise OpenWaiverError("unknown command")
    if hasattr(result, "model_dump"):
        result = result.model_dump(mode="json")
    print(json.dumps(result, indent=2))
    return 0


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (OpenWaiverError, ValueError, OSError) as exc:
        print(f"openwaiver: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
