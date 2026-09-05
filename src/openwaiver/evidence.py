"""Semantic evidence-bundle verification independent of the original database."""
from __future__ import annotations

from datetime import date
import hashlib
import io
import zipfile

from .engine import assess
from .errors import IntegrityError
from .identity import digest
from .importers import strict_json
from .interchange import verify_bundle
from .models import Snapshot
from .store import GENESIS


def verify_evidence(data: bytes) -> dict:
    """Check hashes, audit prefix, frozen records, attachments and policy replay.

    No public key is accepted from inside the bundle. Use verify_file with an
    independently distributed public key for authenticity. A self-consistent,
    unsigned package is still untrusted, even after successful semantic checks.
    """
    basic = verify_bundle(data)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            manifest = strict_json(archive.read("manifest.json").decode())
            snapshot = Snapshot.model_validate(strict_json(archive.read("snapshot.json").decode()))
            events = [strict_json(line) for line in archive.read("audit.jsonl").decode().splitlines()]
            if not events:
                raise IntegrityError("bundle audit history is empty")
            previous, seen = GENESIS, {}
            for number, original in enumerate(events, 1):
                event = dict(original)
                hash_value = event.pop("hash")
                if event["seq"] != number or event["previous"] != previous or digest(event) != hash_value:
                    raise IntegrityError("bundle audit chain or sequence is invalid")
                if "record" in event and digest(event["record"]) != event["content_digest"]:
                    raise IntegrityError("historical waiver content does not match its audit event")
                seen[(event["entity"], event["id"])] = event["content_digest"]
                previous = hash_value
            freeze = events[-1]
            if (manifest["snapshot_id"] != snapshot.id or manifest["audit_head"] != previous
                    or freeze["entity"] != "snapshots" or freeze["id"] != snapshot.id
                    or freeze["content_digest"] != digest(snapshot)
                    or freeze["previous"] != snapshot.audit_head):
                raise IntegrityError("snapshot is not bound to the committed audit prefix")
            if seen.get(("runs", snapshot.run.id)) != digest(snapshot.run):
                raise IntegrityError("snapshot run differs from its audited import")
            if seen.get(("policy", "policy")) != digest(snapshot.policy):
                raise IntegrityError("snapshot policy differs from its audited version")
            expected_waivers = set()
            from .interchange import load_yaml
            for waiver in snapshot.waivers:
                if waiver.scope != snapshot.run.scope:
                    raise IntegrityError("snapshot contains a waiver from another check stream")
                if seen.get(("waivers", waiver.id)) != digest(waiver):
                    raise IntegrityError("snapshot waiver differs from its audited revision")
                name = f"waivers/{waiver.id}.yaml"
                expected_waivers.add(name)
                if digest(load_yaml(archive.read(name).decode())) != digest(waiver):
                    raise IntegrityError("YAML waiver differs from the frozen record")
                for evidence in waiver.evidence:
                    raw = archive.read(f"evidence/{evidence.sha256}")
                    if len(raw) != evidence.size or hashlib.sha256(raw).hexdigest() != evidence.sha256:
                        raise IntegrityError("evidence differs from the reviewed attachment")
                    if seen.get(("evidence", evidence.sha256)) != evidence.sha256:
                        raise IntegrityError("attachment was not included in the audit prefix")
            if {n for n in archive.namelist() if n.startswith("waivers/")} != expected_waivers:
                raise IntegrityError("bundle waiver membership differs from snapshot")
            if len({w.id for w in snapshot.waivers}) != len(snapshot.waivers):
                raise IntegrityError("duplicate snapshot waiver ID")
            assessed_on = date.fromisoformat(snapshot.assessment["assessed_on"])
            replay = assess(snapshot.run, snapshot.waivers, snapshot.policy, assessed_on)
            if replay != snapshot.assessment:
                raise IntegrityError("recorded assessment differs from replay under this engine; review engine-version compatibility")
        return {**basic, "audit_verified": True, "frozen_records_verified": True,
                "assessment_replayed": True, "signature_verified": False,
                "notice": "Internal consistency is not authenticity. Verify an external signature or pinned digest."}
    except IntegrityError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeDecodeError) as exc:
        raise IntegrityError("malformed semantic evidence bundle") from exc
