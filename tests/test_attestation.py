from datetime import timedelta
import hashlib
import io
import json
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from openwaiver.attestation import (Attestation, checkpoint, generate_keypair, load_private,
    load_public, sign_file, verify_checkpoint, verify_file)
from openwaiver.evidence import verify_evidence
from openwaiver.errors import IntegrityError
from openwaiver.identity import canonical
from openwaiver.interchange import bundle, verify_bundle
from openwaiver.models import utcnow


def test_signature_requires_external_matching_key_and_subject():
    key = Ed25519PrivateKey.generate()
    sealed = sign_file(b"evidence", key, "chip/release-A")
    assert verify_file(b"evidence", sealed, key.public_key(), "chip/release-A")["signature_verified"]
    with pytest.raises(IntegrityError):
        verify_file(b"evidence", sealed, Ed25519PrivateKey.generate().public_key(), "chip/release-A")
    with pytest.raises(IntegrityError):
        verify_file(b"evidence", sealed, key.public_key(), "chip/release-B")
    with pytest.raises(IntegrityError):
        verify_file(b"modified", sealed, key.public_key(), "chip/release-A")


@pytest.mark.parametrize("mutation", ["signature", "digest", "key_id", "type"])
def test_modified_envelope_rejected(mutation):
    key = Ed25519PrivateKey.generate()
    envelope = sign_file(b"evidence", key, "release")
    doc = envelope.model_dump(mode="json")
    if mutation == "signature":
        doc["signature"] = "0" * 128
    elif mutation == "digest":
        doc["claim"]["sha256"] = "0" * 64
    elif mutation == "key_id":
        doc["key_id"] = "0" * 64
    else:
        doc["claim"].update(kind="audit-checkpoint", sequence=1)
    with pytest.raises(IntegrityError):
        verify_file(b"evidence", Attestation.model_validate(doc), key.public_key(), "release")


def test_expiry_and_future_issuance_are_enforced():
    key = Ed25519PrivateKey.generate()
    envelope = sign_file(b"a", key, "subject", hours=1)
    with pytest.raises(IntegrityError):
        verify_file(b"a", envelope, key.public_key(), "subject", now=envelope.claim.expires_at)
    with pytest.raises(IntegrityError):
        verify_file(b"a", envelope, key.public_key(), "subject", now=envelope.claim.issued_at - timedelta(seconds=1))


def test_checkpoint_accepts_append_but_detects_replacement(service, make_run):
    key = Ed25519PrivateKey.generate()
    make_run()
    sealed = checkpoint(service.store, key, "workspace-A")
    make_run(revision="later")
    verified = verify_checkpoint(service.store, sealed, key.public_key(), "workspace-A")
    assert verified["events"] > verified["checkpoint_sequence"]
    with pytest.raises(IntegrityError):
        verify_checkpoint(service.store, sealed, key.public_key(), "workspace-A", minimum_sequence=sealed.claim.sequence + 1)
    with pytest.raises(IntegrityError):
        verify_checkpoint(service.store, sealed, key.public_key(), "workspace-A", now=sealed.claim.expires_at)
    with service.store.transaction() as conn:
        conn.execute("DELETE FROM audit WHERE seq=?", (sealed.claim.sequence,))
    with pytest.raises(IntegrityError):
        verify_checkpoint(service.store, sealed, key.public_key(), "workspace-A")


def test_checkpoint_from_other_workspace_rejected(service, tmp_path):
    from openwaiver.store import Store
    key = Ed25519PrivateKey.generate()
    sealed = checkpoint(service.store, key, "subject")
    other = Store(tmp_path / "different.sqlite3")
    with pytest.raises(IntegrityError):
        verify_checkpoint(other, sealed, key.public_key(), "subject")


def test_key_files_are_create_only_and_private_permissions_enforced(tmp_path):
    private, public = tmp_path / "signing.pem", tmp_path / "verify.pem"
    generate_keypair(private, public)
    assert private.stat().st_mode & 0o777 == 0o600
    key = load_private(private)
    envelope = sign_file(b"x", key, "release")
    assert verify_file(b"x", envelope, load_public(public), "release")["valid"]
    with pytest.raises(ValueError):
        generate_keypair(private, public)
    private.chmod(0o644)
    with pytest.raises(ValueError):
        load_private(private)


def test_unknown_algorithm_cannot_be_selected():
    key = Ed25519PrivateKey.generate()
    doc = sign_file(b"x", key, "s").model_dump(mode="json")
    doc["algorithm"] = "none"
    with pytest.raises(ValueError):
        Attestation.model_validate(doc)


def test_semantic_bundle_verification_replays_historical_policy(service, actors, make_run, make_waiver):
    run = make_run()
    waiver = make_waiver(run)
    snapshot = service.freeze(actors["bob"], run.id, "reviewed snapshot")
    service.revoke(actors["alice"], waiver.id, waiver.version, "later revocation")
    data = bundle(service, snapshot.id)
    result = verify_evidence(data)
    assert result["assessment_replayed"] and result["audit_verified"]
    assert not result["signature_verified"] and not result["externally_anchored"]
    key = Ed25519PrivateKey.generate()
    sealed = sign_file(data, key, "chip/release")
    assert verify_file(data, sealed, key.public_key(), "chip/release")["valid"]


def repackage(data, filename, value):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        files = {name: z.read(name) for name in z.namelist()}
    files[filename] = value
    manifest = json.loads(files["manifest.json"])
    manifest["files"][filename] = hashlib.sha256(value).hexdigest()
    files["manifest.json"] = canonical(manifest).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        for name, raw in files.items():
            z.writestr(name, raw)
    return output.getvalue()


@pytest.mark.parametrize("target", ["snapshot", "audit", "waiver"])
def test_rehashed_but_inconsistent_bundle_is_rejected(service, actors, make_run, make_waiver, target):
    run = make_run()
    waiver = make_waiver(run)
    snapshot = service.freeze(actors["bob"], run.id, "snapshot")
    data = bundle(service, snapshot.id)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if target == "snapshot":
            name = "snapshot.json"
            doc = json.loads(z.read(name))
            doc["assessment"]["gate_pass"] = False
            value = canonical(doc).encode()
        elif target == "audit":
            name = "audit.jsonl"
            value = b"\n".join(z.read(name).splitlines()[1:]) + b"\n"
        else:
            name = f"waivers/{waiver.id}.yaml"
            value = z.read(name).replace(b"alice", b"mallory")
    forged = repackage(data, name, value)
    assert verify_bundle(forged)["valid"]  # All file checksums were regenerated.
    with pytest.raises(IntegrityError):
        verify_evidence(forged)  # Audit binding / historical content still catches it.
