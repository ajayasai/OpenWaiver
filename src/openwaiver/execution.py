"""Scope-authorized producer receipts. Signatures authenticate claims, not executions.

Trust is supplied separately by an operator; neither a request nor an archive can
install a trusted key. Producer and release-publisher keys must be different.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, model_validator

from .attestation import Attestation, Claim, key_id, sign_claim, verify_file
from .errors import IntegrityError, OpenWaiverError
from .identity import canonical, digest
from .importers import strict_json
from .models import Model, Run, Scope, utcnow

HASH = r"^[a-f0-9]{64}$"


def aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp requires a timezone")
    return value


def public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are accepted")
    return key


class KeyGrant(Model):
    public_key_pem: str = Field(max_length=10000)
    not_before: datetime
    not_after: datetime
    revoked: bool = False

    @model_validator(mode="after")
    def valid_key(self):
        public_key(self.public_key_pem)
        if aware(self.not_after) <= aware(self.not_before):
            raise ValueError("key validity interval is empty")
        return self

    def authorize_time(self, when: datetime):
        if self.revoked or not self.not_before <= aware(when) < self.not_after:
            raise IntegrityError("signer revoked or outside its authorized validity interval")


class ProducerGrant(KeyGrant):
    scopes: list[Scope] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def distinct_scopes(self):
        if len({digest(s) for s in self.scopes}) != len(self.scopes):
            raise ValueError("duplicate producer scope grant")
        return self


class PublisherGrant(KeyGrant):
    projects: list[str] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def distinct_projects(self):
        if len(set(self.projects)) != len(self.projects):
            raise ValueError("duplicate publisher project grant")
        for project in self.projects:
            if Scope(project=project, stream="check", tool="tool").project != project:
                raise ValueError("publisher project must be canonical")
        return self


class ReleaseTrust(Model):
    schema_version: Literal[1] = 1
    approved_contracts: list[Annotated[str, Field(pattern=HASH)]] = Field(default_factory=list, max_length=10000)
    producers: list[ProducerGrant] = Field(min_length=1, max_length=128)
    publishers: list[PublisherGrant] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def separate_keys(self):
        if len(self.approved_contracts) != len(set(self.approved_contracts)):
            raise ValueError("duplicate approved contract digest")
        identifiers = [key_id(public_key(g.public_key_pem)) for g in self.producers + self.publishers]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("keys must be unique; execution and publication require separate keys")
        return self

    def resolve(self, identifier: str, purpose: str, scope: Scope, at: datetime, now: datetime):
        grants = self.producers if purpose == "producer" else self.publishers if purpose == "publisher" else []
        for grant in grants:
            key = public_key(grant.public_key_pem)
            if key_id(key) != identifier:
                continue
            grant.authorize_time(at)
            grant.authorize_time(now)
            allowed = scope in grant.scopes if isinstance(grant, ProducerGrant) else scope.project in grant.projects
            if not allowed:
                raise IntegrityError("signer is not authorized for this exact scope or project")
            return key
        raise IntegrityError("signer is not in the independently supplied trust policy")


def read_trust(path: Path) -> ReleaseTrust:
    if path.is_symlink():
        raise OpenWaiverError("symlink trust policy rejected")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise OpenWaiverError("trust policy exceeds 1 MiB")
    return ReleaseTrust.model_validate(strict_json(raw.decode("utf-8")))


class ExecutionClaim(Model):
    schema_version: Literal[1] = 1
    run_id: str = Field(min_length=1, max_length=200)
    run_sha256: str = Field(pattern=HASH)
    design_sha256: str = Field(pattern=HASH)
    invocation_sha256: str = Field(pattern=HASH)
    stdout_sha256: str = Field(pattern=HASH)
    stderr_sha256: str = Field(pattern=HASH)
    started_at: datetime
    finished_at: datetime
    exit_code: int = Field(strict=True)
    complete: bool
    unfiltered: bool

    @model_validator(mode="after")
    def time_order(self):
        if aware(self.started_at) > aware(self.finished_at):
            raise ValueError("execution finishes before it starts")
        return self


class ExecutionReceipt(Model):
    claim: ExecutionClaim
    attestation: Attestation


def execution_subject(run_id: str) -> str:
    return "openwaiver.execution.v1:" + run_id


def sign_execution(claim: ExecutionClaim, key: Ed25519PrivateKey, *, now: datetime | None = None,
                   hours: float = 24) -> ExecutionReceipt:
    claim = ExecutionClaim.model_validate(claim.model_dump(mode="json"))
    now = aware(now or utcnow())
    if not 0 < hours <= 8760 or claim.finished_at > now:
        raise ValueError("invalid receipt lifetime or future execution")
    seal = sign_claim(Claim(kind="file", subject=execution_subject(claim.run_id), sequence=0,
                           sha256=digest(claim), issued_at=now, expires_at=now + timedelta(hours=hours)), key)
    return ExecutionReceipt(claim=claim, attestation=seal)


def verify_execution(receipt: ExecutionReceipt, run: Run, design_sha256: str, trust: ReleaseTrust,
                     now: datetime, max_age_hours: float) -> dict:
    receipt = ExecutionReceipt.model_validate(receipt.model_dump(mode="json"))
    now = aware(now)
    claim, seal = receipt.claim, receipt.attestation
    key = trust.resolve(seal.key_id, "producer", run.scope, seal.claim.issued_at, now)
    verify_file(canonical(claim).encode(), seal, key, execution_subject(run.id), now=now)
    if claim.run_id != run.id or claim.run_sha256 != digest(run):
        raise IntegrityError("receipt does not bind this exact imported run")
    if claim.design_sha256 != design_sha256:
        raise IntegrityError("receipt design digest differs from the release contract")
    if not claim.complete or not claim.unfiltered or claim.exit_code != 0:
        raise IntegrityError("producer did not attest a successful complete unfiltered execution")
    if not claim.finished_at <= aware(run.created_at) <= seal.claim.issued_at <= now:
        raise IntegrityError("execution, import and signature timestamps are inconsistent")
    age_hours = (now - claim.finished_at).total_seconds() / 3600
    if not 0 <= age_hours <= max_age_hours:
        raise IntegrityError("execution is future-dated or exceeds freshness bound")
    return {"key_id": seal.key_id, "finished_at": claim.finished_at.isoformat(),
            "execution_age_hours": age_hours, "receipt_sha256": digest(receipt)}
