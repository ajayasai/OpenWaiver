"""Portable, signed multi-tool release capsules with independent policy replay.

No extraction, network access, imported keys, executable pickles, or server-side
private keys. The caller supplies the reviewed contract and trust policy separately.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import io
import re
import stat
from typing import Literal
import zipfile

from pydantic import Field

from . import __version__
from .assurance import ReleaseContract, capture_inventory, evaluate_contract
from .attestation import Attestation, Claim, key_id, sign_claim, verify_file
from .errors import IntegrityError, OpenWaiverError
from .execution import ExecutionReceipt, ReleaseTrust, aware
from .identity import canonical, digest
from .importers import strict_json
from .models import Model, Policy, Run, Scope, Waiver, utcnow

MAX_CAPSULE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 10003


class ReleaseRecord(Model):
    schema_version: Literal[1] = 1
    engine_version: str
    contract: ReleaseContract
    assessed_at: datetime
    policy: Policy
    runs: list[Run] = Field(max_length=1000)
    waivers: list[Waiver] = Field(max_length=250000)
    receipts: list[ExecutionReceipt] = Field(max_length=1000)
    result: dict


def capsule_subject(contract: ReleaseContract) -> str:
    return "openwaiver.release.v1:" + digest(contract)


def seal_capsule(service, contract, receipts, trust, key, *, hours=24, now=None,
                 allow_blocked=False, actor=None) -> bytes:
    now = aware(now or utcnow())
    contract = ReleaseContract.model_validate(contract.model_dump(mode="json"))
    trust = ReleaseTrust.model_validate(trust.model_dump(mode="json"))
    if not 0 < hours <= 8760:
        raise ValueError("invalid capsule lifetime")
    scope = Scope(project=contract.manifest.project, stream="release", tool="openwaiver")
    trust.resolve(key_id(key.public_key()), "publisher", scope, now, now)
    inventory = capture_inventory(service, contract, actor, include_evidence=True)
    evidence = inventory.pop("evidence")
    result = evaluate_contract(contract, **inventory, receipts=receipts, trust=trust, now=now)
    if not result["gate_pass"] and not allow_blocked:
        raise OpenWaiverError("release blocked; inspect the gate or explicitly seal a diagnostic capsule")
    record = ReleaseRecord(engine_version=__version__, contract=contract, assessed_at=now,
                           **inventory, receipts=receipts, result=result)
    files = {"release.json": canonical(record).encode()}
    files.update({f"evidence/{sha}": data for sha, data in evidence.items()})
    if len(files) + 2 > MAX_MEMBERS or sum(map(len, files.values())) > MAX_EXPANDED_BYTES - 1024 * 1024:
        raise OpenWaiverError("capsule evidence budget exceeded")
    manifest = canonical({"schema_version": 1, "files": {name: hashlib.sha256(data).hexdigest()
                                                         for name, data in sorted(files.items())}}).encode()
    seal = sign_claim(Claim(kind="file", subject=capsule_subject(contract), sequence=0,
                           sha256=hashlib.sha256(manifest).hexdigest(), issued_at=now,
                           expires_at=now + timedelta(hours=hours)), key)
    files.update({"manifest.json": manifest, "attestation.json": canonical(seal).encode()})
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, data)
    data = output.getvalue()
    if len(data) > MAX_CAPSULE_BYTES:
        raise OpenWaiverError("compressed capsule exceeds byte budget")
    return data


def _read_archive(data):
    if len(data) > MAX_CAPSULE_BYTES:
        raise IntegrityError("compressed capsule exceeds byte budget")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = {entry.filename for entry in entries}
        if len(names) != len(entries) or len(entries) > MAX_MEMBERS:
            raise IntegrityError("duplicate or excessive capsule members")
        if sum(e.file_size for e in entries) > MAX_EXPANDED_BYTES:
            raise IntegrityError("expanded capsule exceeds byte budget")
        required = {"release.json", "manifest.json", "attestation.json"}
        if not required <= names or any(n not in required and not re.fullmatch(r"evidence/[a-f0-9]{64}", n) for n in names):
            raise IntegrityError("unsafe or unexpected capsule member")
        for entry in entries:
            if (entry.flag_bits & 1 or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise IntegrityError("unsupported capsule member encoding")
        return {entry.filename: archive.read(entry) for entry in entries}


def verify_capsule(data: bytes, contract: ReleaseContract, trust: ReleaseTrust,
                   now: datetime | None = None, *, service=None, actor=None) -> dict:
    """Authenticate publisher, exact inventory and receipts; replay historical and current gates.

    A historically clean capsule may no longer be usable due to expiry, execution
    age or revocation. Both decisions are returned, never conflated with authenticity.
    """
    now = aware(now or utcnow())
    contract = ReleaseContract.model_validate(contract.model_dump(mode="json"))
    trust = ReleaseTrust.model_validate(trust.model_dump(mode="json"))
    try:
        files = _read_archive(data)
        seal = Attestation.model_validate(strict_json(files["attestation.json"].decode()))
        scope = Scope(project=contract.manifest.project, stream="release", tool="openwaiver")
        key = trust.resolve(seal.key_id, "publisher", scope, seal.claim.issued_at, now)
        verify_file(files["manifest.json"], seal, key, capsule_subject(contract), now=now)
        manifest = strict_json(files["manifest.json"].decode())
        if set(manifest) != {"schema_version", "files"} or manifest["schema_version"] != 1:
            raise IntegrityError("unsupported capsule manifest")
        if set(manifest["files"]) != set(files) - {"manifest.json", "attestation.json"}:
            raise IntegrityError("capsule membership differs from signed manifest")
        for name, checksum in manifest["files"].items():
            if hashlib.sha256(files[name]).hexdigest() != checksum:
                raise IntegrityError("capsule member differs from signed digest")
        record = ReleaseRecord.model_validate(strict_json(files["release.json"].decode()))
        if digest(record.contract) != digest(contract):
            raise IntegrityError("capsule contract differs from the independently supplied contract")
        if record.engine_version != __version__:
            raise IntegrityError("replay engine version mismatch; use the recorded version in an isolated environment")
        if aware(record.assessed_at) != seal.claim.issued_at or record.assessed_at > now:
            raise IntegrityError("release assessment is not bound to the signature time")
        evidence_names = set()
        for waiver in record.waivers:
            for evidence in waiver.evidence:
                name = f"evidence/{evidence.sha256}"
                evidence_names.add(name)
                raw = files.get(name)
                if raw is None or len(raw) != evidence.size or hashlib.sha256(raw).hexdigest() != evidence.sha256:
                    raise IntegrityError("reviewed attachment missing or changed")
        if {n for n in files if n.startswith("evidence/")} != evidence_names:
            raise IntegrityError("extra or missing evidence in capsule")
        args = {"contract": contract, "runs": record.runs, "waivers": record.waivers,
                "policy": record.policy, "receipts": record.receipts, "trust": trust}
        replay = evaluate_contract(**args, now=record.assessed_at)
        if replay != record.result:
            raise IntegrityError("release decision does not replay under the independently supplied trust policy")
        current = evaluate_contract(**args, now=now)
        live_matches, live_pass = None, None
        if service is not None:
            live = capture_inventory(service, contract, actor)
            frozen = {"runs": sorted(record.runs, key=lambda r: r.id),
                      "waivers": sorted(record.waivers, key=lambda w: w.id), "policy": record.policy}
            live_matches = all(digest([x.model_dump(mode="json") for x in live[k]]) ==
                               digest([x.model_dump(mode="json") for x in frozen[k]])
                               for k in ("runs", "waivers")) and digest(live["policy"]) == digest(record.policy)
            live_pass = evaluate_contract(contract, **live, receipts=record.receipts, trust=trust, now=now)["gate_pass"]
        return {"valid": True, "publisher_authenticated": True, "historical_assessment_replayed": True,
                "publisher_key_id": seal.key_id, "contract_sha256": digest(contract),
                "historical_gate_pass": replay["gate_pass"], "frozen_state_gate_pass_now": current["gate_pass"],
                "live_state_checked": service is not None, "live_state_matches": live_matches,
                "live_gate_pass": live_pass,
                "release_usable_now": (current["gate_pass"] and live_matches and live_pass) if service is not None else None,
                "frozen_state_assessment_now": current,
                "historical_assessed_at": record.assessed_at.isoformat(), "evidence_files": len(evidence_names),
                "notice": "Offline replay cannot discover later waiver revocations or database changes. For current release use, reconcile against the live database. Publisher and producer claims remain trusted inputs, not proof of engineering correctness."}
    except IntegrityError:
        raise
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, zipfile.BadZipFile, RuntimeError, RecursionError,
            OpenWaiverError) as exc:
        raise IntegrityError("malformed or unverifiable release capsule") from exc
