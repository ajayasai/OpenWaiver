"""Offline Ed25519 signatures with externally pinned public keys and explicit subjects.

This is a small versioned OpenWaiver envelope, NOT DSSE/Sigstore, trusted timestamping,
PKI, WORM storage or proof that an EDA execution actually took place. Signing keys
stay with a trusted local operator; the HTTP server has no signing-key endpoint.
"""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from .errors import IntegrityError, OpenWaiverError
from .identity import canonical
from .models import Model, utcnow

DOMAIN = b"OpenWaiver attestation v1\x00"


class Claim(Model):
    kind: Literal["file", "audit-checkpoint"]
    subject: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    sequence: int = Field(ge=0)
    issued_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def bounds(self):
        if not self.subject.strip():
            raise ValueError("subject cannot be blank")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("attestation timestamps require timezones")
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expiry must follow issuance")
        if self.kind == "file" and self.sequence != 0:
            raise ValueError("file signatures must use sequence zero")
        if self.kind == "audit-checkpoint" and self.sequence < 1:
            raise ValueError("checkpoint must include an audit event")
        return self


class Attestation(Model):
    schema_version: Literal[1] = 1
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    claim: Claim
    signature: str = Field(pattern=r"^[a-f0-9]{128}$")


def key_id(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def generate_keypair(private_path: Path, public_path: Path) -> dict:
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise OpenWaiverError("key output files must be distinct and must not exist")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    created = []
    try:
        for path, content, mode in ((private_path, private, 0o600), (public_path, public, 0o644)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {"key_id": key_id(key.public_key()), "private_file": str(private_path), "public_file": str(public_path)}


def load_private(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink() or (os.name == "posix" and path.stat().st_mode & 0o077):
        raise OpenWaiverError("private key must be a non-symlink file readable only by its owner (chmod 600)")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise OpenWaiverError("only Ed25519 signing keys are accepted")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise OpenWaiverError("only Ed25519 verification keys are accepted")
    return key


def sign_claim(claim: Claim, key: Ed25519PrivateKey) -> Attestation:
    return Attestation(key_id=key_id(key.public_key()), claim=claim,
                       signature=key.sign(DOMAIN + canonical(claim).encode()).hex())


def verify_claim(envelope: Attestation, key: Ed25519PublicKey, *, subject: str, kind: str,
                 minimum_sequence: int = 0, now: datetime | None = None) -> Claim:
    # Revalidate callers' model_copy updates, too; never trust a forged model instance.
    envelope = Attestation.model_validate(envelope.model_dump(mode="json"))
    now = now or utcnow()
    if now.tzinfo is None or minimum_sequence < 0:
        raise ValueError("verification needs aware time and a nonnegative minimum sequence")
    if envelope.key_id != key_id(key):
        raise IntegrityError("signing key is not the independently supplied trusted key")
    try:
        key.verify(bytes.fromhex(envelope.signature), DOMAIN + canonical(envelope.claim).encode())
    except InvalidSignature as exc:
        raise IntegrityError("Ed25519 signature invalid") from exc
    claim = envelope.claim
    if claim.subject != subject or claim.kind != kind:
        raise IntegrityError("signed subject or claim type does not match the expected purpose")
    if not claim.issued_at <= now < claim.expires_at:
        raise IntegrityError("attestation is future-dated or expired")
    if claim.sequence < minimum_sequence:
        raise IntegrityError("checkpoint predates the externally retained minimum sequence")
    return claim


def sign_file(data: bytes, key: Ed25519PrivateKey, subject: str, hours: float = 24) -> Attestation:
    now = utcnow()
    if not 0 < hours <= 8760:
        raise ValueError("signature lifetime must be greater than zero and at most one year")
    return sign_claim(Claim(kind="file", subject=subject, sequence=0,
        sha256=hashlib.sha256(data).hexdigest(), issued_at=now, expires_at=now + timedelta(hours=hours)), key)


def verify_file(data: bytes, envelope: Attestation, key: Ed25519PublicKey, subject: str,
                now: datetime | None = None) -> dict:
    claim = verify_claim(envelope, key, subject=subject, kind="file", now=now)
    if hashlib.sha256(data).hexdigest() != claim.sha256:
        raise IntegrityError("signed artifact bytes changed")
    return {"valid": True, "signature_verified": True, "key_id": key_id(key),
            "subject": subject, "sha256": claim.sha256}


def checkpoint(store, key: Ed25519PrivateKey, subject: str, hours: float = 24) -> Attestation:
    if not 0 < hours <= 8760:
        raise ValueError("checkpoint lifetime must be greater than zero and at most one year")
    with store.transaction(write=False) as conn:
        result = store.verify(conn)
        now = utcnow()
        claim = Claim(kind="audit-checkpoint", subject=subject, sha256=result["head"],
                      sequence=result["events"], issued_at=now, expires_at=now + timedelta(hours=hours))
        return sign_claim(claim, key)


def verify_checkpoint(store, envelope: Attestation, key: Ed25519PublicKey, subject: str,
                      minimum_sequence: int = 0, now: datetime | None = None) -> dict:
    claim = verify_claim(envelope, key, subject=subject, kind="audit-checkpoint",
                         minimum_sequence=minimum_sequence, now=now)
    with store.transaction(write=False) as conn:
        verified = store.verify(conn)
        row = conn.execute("SELECT hash FROM audit WHERE seq=?", (claim.sequence,)).fetchone()
        if row is None or row[0] != claim.sha256:
            raise IntegrityError("database was truncated, replaced or forked before the signed checkpoint")
    return {**verified, "signature_verified": True, "checkpoint_sequence": claim.sequence,
            "checkpoint_head": claim.sha256, "subject": subject, "key_id": key_id(key),
            "externally_anchored": True}
