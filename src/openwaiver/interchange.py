"""Deterministic Git projections and integrity-checkable evidence bundles."""
from __future__ import annotations

import hashlib
import hmac
import io
from pathlib import Path
import re
import zipfile

import yaml

from .errors import IntegrityError, OpenWaiverError
from .exporters import export_report
from .identity import canonical, digest, fingerprint
from .importers import strict_json
from .models import Principal, Waiver, utcnow, uid


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise OpenWaiverError("YAML aliases are not accepted")
        return super().compose_node(parent, index)


def unique_mapping(loader, node, deep=False):
    out = {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in out:
            raise OpenWaiverError(f"duplicate YAML key: {key}")
        out[key] = loader.construct_object(v, deep=deep)
    return out


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def _load_yaml(text: str):
    if len(text.encode()) > 4 * 1024 * 1024:
        raise OpenWaiverError("YAML exceeds 4 MiB")
    # A bounded nesting check prevents stack exhaustion before constructing data.
    depth = 0
    for event in yaml.parse(text):
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
            if depth > 40:
                raise OpenWaiverError("YAML nesting exceeds limit")
        if isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
    return yaml.load(text, Loader=StrictLoader)


def load_yaml(text: str):
    try:
        return _load_yaml(text)
    except (yaml.YAMLError, TypeError) as exc:
        raise OpenWaiverError(f"invalid YAML: {exc}") from exc


def git_export(service, destination: Path) -> dict:
    # Create-only exports: no mixing stale files from an old snapshot into a new one.
    if destination.exists():
        raise OpenWaiverError("Git export destination must not exist; review and replace it explicitly")
    with service.store.transaction(write=False) as conn:
        service.store.verify(conn)
        waivers = service.store.all(conn, "waivers")
        policy = service.store.policy(conn)
        head = service.store.head(conn)
        files = {f"waivers/{w.id}.yaml": yaml.safe_dump(w.model_dump(mode="json"), sort_keys=False,
                                                     allow_unicode=True, width=100) for w in waivers}
        files["policy.yaml"] = yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False)
        files["manifest.yaml"] = yaml.safe_dump({"schema_version": 1, "audit_head": head,
            "files": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in sorted(files.items())}}, sort_keys=False)
    destination.mkdir(parents=True)
    for name, content in files.items():
        p = destination / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return {"waivers": len(waivers), "audit_head": head, "destination": str(destination)}


def import_yaml_proposal(service, actor: Principal, text: str) -> Waiver:
    """Never trust approval/status/evidence bytes supplied in an editable YAML record."""
    service.role(actor, "contributor", "reviewer", "admin")
    old = Waiver.model_validate(load_yaml(text))
    service.project(actor, old.scope.project)
    data = old.model_dump()
    data.update(id=uid("wvr"), version=1, creator=actor.name, owner=actor.name,
                status="proposed", approvals=[], evidence=[], created_at=utcnow(), updated_at=utcnow())
    w = Waiver.model_validate(data)
    with service.store.transaction() as conn:
        service.store.verify(conn)
        run = service.store.get(conn, "runs", w.baseline_run_id)
        target = next((v for v in run.violations if v.id == w.target.id), None)
        if (target is None or target != w.target or run.scope != w.scope
                or fingerprint(target) != w.fingerprint or run.revision != w.baseline_revision):
            raise OpenWaiverError("YAML target must match an existing immutable run")
        from .engine import provenance
        if w.baseline_provenance != provenance(run):
            raise OpenWaiverError("YAML baseline provenance differs from imported run")
        if any(x.scope == w.scope and x.fingerprint == w.fingerprint and x.status != "revoked"
               for x in service.store.all(conn, "waivers")):
            raise OpenWaiverError("target already has a waiver; amend it instead")
        service._check_bounds(w, service.store.policy(conn))
        service.store.save(conn, "waivers", w, actor.name, "yaml-import:untrusted-approval-reset", create=True)
    return w


def bundle(service, snapshot_id: str, key: bytes | None = None) -> bytes:
    if key is not None and len(key) < 32:
        raise IntegrityError("HMAC keys must contain at least 32 bytes")
    with service.store.transaction(write=False) as conn:
        service.store.verify(conn)
        snap = service.store.get(conn, "snapshots", snapshot_id)
        all_events = service.store.events(conn)
        freeze = next((e for e in all_events if e["entity"] == "snapshots" and e["id"] == snapshot_id), None)
        if freeze is None:
            raise IntegrityError("snapshot has no committed freeze event")
        captured_events = [e for e in all_events if e["seq"] <= freeze["seq"]]
        files = {"snapshot.json": canonical(snap).encode(),
                 "assessment.sarif": export_report(snap.assessment, "sarif").encode(),
                 "assessment.html": export_report(snap.assessment, "html").encode(),
                 "audit.jsonl": ("\n".join(canonical(e) for e in captured_events) + "\n").encode()}
        for w in snap.waivers:
            files[f"waivers/{w.id}.yaml"] = yaml.safe_dump(w.model_dump(mode="json"), sort_keys=False).encode()
            for ev in w.evidence:
                row = conn.execute("SELECT data FROM evidence WHERE sha256=?", (ev.sha256,)).fetchone()
                if row is None:
                    raise IntegrityError("snapshot evidence missing")
                files[f"evidence/{ev.sha256}"] = row[0]
        manifest = {"schema_version": 1, "snapshot_id": snap.id,
                    "audit_head": freeze["hash"],
                    "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())}}
        files["manifest.json"] = canonical(manifest).encode()
        if key:
            files["manifest.hmac-sha256"] = hmac.new(key, files["manifest.json"], hashlib.sha256).hexdigest().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    return output.getvalue()


def _verify_bundle(data: bytes, key: bytes | None = None, expected_manifest: str | None = None) -> dict:
    if key is not None and len(key) < 32:
        raise IntegrityError("HMAC keys must contain at least 32 bytes")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [x.filename for x in entries]
        if len(names) != len(set(names)) or len(names) > 100000:
            raise IntegrityError("duplicate or excessive ZIP members")
        if sum(x.file_size for x in entries) > 256 * 1024 * 1024:
            raise IntegrityError("expanded bundle exceeds 256 MiB")
        if any(not re.fullmatch(r"[A-Za-z0-9_./-]+", n) or n.startswith("/") or ".." in n.split("/") for n in names):
            raise IntegrityError("unsafe ZIP member path")
        raw = archive.read("manifest.json")
        manifest = strict_json(raw.decode())
        if manifest.get("schema_version") != 1:
            raise IntegrityError("unsupported bundle manifest")
        sha = hashlib.sha256(raw).hexdigest()
        if expected_manifest is not None and expected_manifest != sha:
            raise IntegrityError("external manifest digest mismatch")
        if key:
            expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
            if "manifest.hmac-sha256" not in names or not hmac.compare_digest(expected, archive.read("manifest.hmac-sha256").decode()):
                raise IntegrityError("HMAC seal missing or invalid")
        payload = set(names) - {"manifest.json", "manifest.hmac-sha256"}
        if payload != set(manifest["files"]):
            raise IntegrityError("bundle manifest membership mismatch")
        for name, checksum in manifest["files"].items():
            if hashlib.sha256(archive.read(name)).hexdigest() != checksum:
                raise IntegrityError(f"bundle content mismatch: {name}")
    return {"valid": True, "hmac_verified": key is not None,
            "externally_anchored": key is not None or expected_manifest is not None,
            "manifest_sha256": sha, "files": len(payload), "snapshot_id": manifest["snapshot_id"]}


def verify_bundle(data: bytes, key: bytes | None = None, expected_manifest: str | None = None) -> dict:
    try:
        return _verify_bundle(data, key, expected_manifest)
    except (zipfile.BadZipFile, KeyError, TypeError, UnicodeDecodeError, RuntimeError) as exc:
        raise IntegrityError(f"invalid evidence bundle: {exc}") from exc
