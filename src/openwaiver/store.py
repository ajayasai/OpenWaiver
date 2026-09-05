"""SQLite authority with atomic audit events, optimistic versions and content verification.

The audit chain is tamper-evident against an externally saved head, NOT an immutable
ledger against a database administrator who can replace both state and all hashes.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
from pathlib import Path
import sqlite3

from .errors import IntegrityError, NotFound
from .identity import canonical, digest
from .importers import strict_json
from .models import Policy, Run, Snapshot, Waiver, utcnow

GENESIS = "0" * 64
TABLES = {"runs": Run, "waivers": Waiver, "snapshots": Snapshot}


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS waivers (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS snapshots (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS evidence (
                    sha256 TEXT PRIMARY KEY, data BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY, event TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);
            """)
            conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', '1')")
            if conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] != "1":
                raise IntegrityError("unsupported database schema")
        with self.transaction() as conn:
            if conn.execute("SELECT 1 FROM meta WHERE key='policy'").fetchone() is None:
                policy = Policy()
                conn.execute("INSERT INTO meta VALUES ('policy', ?)", (canonical(policy),))
                self.event(conn, "system", "initialize", "policy", "policy", digest(policy))

    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def transaction(self, *, write: bool = True):
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def policy(self, conn) -> Policy:
        row = conn.execute("SELECT value FROM meta WHERE key='policy'").fetchone()
        return Policy.model_validate_json(row[0])

    def get(self, conn, table: str, id: str):
        if table not in TABLES:
            raise ValueError("invalid collection")
        row = conn.execute(f"SELECT data FROM {table} WHERE id=?", (id,)).fetchone()
        if row is None:
            raise NotFound(f"{table} record not found")
        return TABLES[table].model_validate_json(row[0])

    def all(self, conn, table: str):
        if table not in TABLES:
            raise ValueError("invalid collection")
        return [TABLES[table].model_validate_json(r[0])
                for r in conn.execute(f"SELECT data FROM {table} ORDER BY rowid")]

    def save(self, conn, table: str, record, actor: str, action: str, *, create: bool = False):
        if table not in TABLES:
            raise ValueError("invalid collection")
        if create:
            conn.execute(f"INSERT INTO {table}(id,data) VALUES (?,?)", (record.id, canonical(record)))
        else:
            cur = conn.execute(f"UPDATE {table} SET data=? WHERE id=?", (canonical(record), record.id))
            if cur.rowcount != 1:
                raise NotFound("record disappeared during update")
        self.event(conn, actor, action, table, record.id, digest(record),
                   record.model_dump(mode="json") if table == "waivers" else None)

    def event(self, conn, actor: str, action: str, entity: str, id: str, content_digest: str, record=None):
        row = conn.execute("SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        event = {"seq": row[0] + 1 if row else 1, "previous": row[1] if row else GENESIS,
                 "at": utcnow().isoformat(), "actor": actor, "action": action,
                 "entity": entity, "id": id, "content_digest": content_digest}
        if record is not None:
            event["record"] = record
        h = digest(event)
        conn.execute("INSERT INTO audit VALUES (?,?,?)", (event["seq"], canonical(event), h))
        return h

    def head(self, conn) -> str:
        row = conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def events(self, conn) -> list[dict]:
        return [{**strict_json(row[0]), "hash": row[1]}
                for row in conn.execute("SELECT event,hash FROM audit ORDER BY seq")]

    def verify(self, conn, expected_head: str | None = None) -> dict:
        previous, seen, expected_seq = GENESIS, {}, 1
        for row in conn.execute("SELECT seq,event,hash FROM audit ORDER BY seq"):
            event = strict_json(row[1])
            if (row[0] != expected_seq or event["seq"] != expected_seq
                    or event["previous"] != previous or digest(event) != row[2]):
                raise IntegrityError(f"audit chain invalid at event {expected_seq}")
            if "record" in event and digest(event["record"]) != event["content_digest"]:
                raise IntegrityError("audited revision content mismatch")
            previous, expected_seq = row[2], expected_seq + 1
            seen[(event["entity"], event["id"])] = event["content_digest"]
        if not seen:
            raise IntegrityError("audit history missing")
        if expected_head is not None and expected_head != previous:
            raise IntegrityError("external audit checkpoint mismatch")
        live = {("policy", "policy"): digest(self.policy(conn))}
        for table in TABLES:
            for record in self.all(conn, table):
                live[(table, record.id)] = digest(record)
        for row in conn.execute("SELECT sha256,data FROM evidence"):
            actual = hashlib.sha256(row[1]).hexdigest()
            if actual != row[0]:
                raise IntegrityError("evidence bytes changed")
            live[("evidence", row[0])] = actual
        if live != seen:
            raise IntegrityError("database state does not match audited content")
        for w in self.all(conn, "waivers"):
            for ev in w.evidence:
                row = conn.execute("SELECT length(data) FROM evidence WHERE sha256=?", (ev.sha256,)).fetchone()
                if row is None or row[0] != ev.size:
                    raise IntegrityError("missing evidence or evidence length mismatch")
        return {"valid": True, "events": expected_seq - 1, "head": previous,
                "externally_anchored": expected_head is not None}
