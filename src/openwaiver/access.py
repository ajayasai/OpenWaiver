"""Server-owned project grants and reloadable, expiring token registries.

Legacy tokens without projects remain workspace-wide for compatibility. CLI and
DB filesystem access are trusted operator interfaces, not authentication boundaries.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import Field, model_validator

from .errors import Forbidden, OpenWaiverError
from .importers import strict_json
from .models import Model, Principal, utcnow


class TokenRecord(Model):
    name: str
    role: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    projects: list[str] | None = None
    expires_at: datetime | None = None
    revoked: bool = False

    @model_validator(mode="after")
    def validate_identity(self):
        Principal(name=self.name, role=self.role, projects=self.projects)
        if self.expires_at and self.expires_at.tzinfo is None:
            raise ValueError("token expiry requires a timezone")
        return self

    def active(self):
        return not self.revoked and (self.expires_at is None or utcnow() < self.expires_at)


def validate_records(records: list[dict]) -> list[TokenRecord]:
    if not records or len(records) > 10000:
        raise OpenWaiverError("authentication registry needs 1..10000 records")
    result = [TokenRecord.model_validate(x) for x in records]
    if len({x.sha256 for x in result}) != len(result):
        raise OpenWaiverError("duplicate token digest")
    return result


def token_records(path: Path) -> list[dict]:
    if path.is_symlink():
        raise OpenWaiverError("symbolic-link token registry rejected")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise OpenWaiverError("authentication registry exceeds 1 MiB")
    doc = strict_json(raw.decode("utf-8"))
    if not isinstance(doc, dict) or set(doc) != {"tokens"}:
        raise OpenWaiverError("registry must contain only a tokens array")
    return [x.model_dump(mode="json") for x in validate_records(doc["tokens"])]


def workspace_only(actor: Principal):
    if actor.projects is not None:
        raise Forbidden("this operation exposes the shared workspace ledger; an unrestricted identity is required")


def visible_events(service, conn, actor: Principal):
    events = service.store.events(conn)
    if actor.projects is None:
        return events
    permitted = set()
    for table in ("runs", "waivers", "snapshots"):
        for item in service.store.all(conn, table):
            if service.visible(actor, item):
                permitted.add((table, item.id))
    return [e for e in events if (e["entity"], e["id"]) in permitted]
