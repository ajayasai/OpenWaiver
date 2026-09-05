"""The same authorization and review rules are shared by CLI and API."""
from __future__ import annotations

from datetime import date
import hashlib
from pathlib import Path
import re

from .engine import approval_problems, assess, provenance
from .errors import Conflict, Forbidden, NotFound, OpenWaiverError
from .identity import approval_digest, digest, fingerprint
from .importers import parse_report, strict_json
from .models import Approval, Evidence, Policy, Principal, Run, Scope, Snapshot, Violation, Waiver, utcnow
from .store import Store


class Service:
    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def visible(actor: Principal | None, record) -> bool:
        project = record.run.scope.project if isinstance(record, Snapshot) else record.scope.project
        return actor is None or actor.projects is None or project in actor.projects

    @staticmethod
    def project(actor: Principal, project: str):
        if actor.projects is not None and project not in actor.projects:
            # Do not reveal whether a guessed foreign record exists.
            raise NotFound("record not found in authorized projects")

    def read(self, conn, table, id, actor: Principal | None):
        item = self.store.get(conn, table, id)
        if not self.visible(actor, item):
            raise NotFound("record not found in authorized projects")
        return item

    @staticmethod
    def role(actor: Principal, *roles: str):
        if actor.role not in roles:
            raise Forbidden("role is not permitted for this operation")

    @staticmethod
    def owner(actor: Principal, w: Waiver):
        if actor.role != "admin" and actor.name != w.owner:
            raise Forbidden("only the owner or an administrator can modify this waiver")

    def _load(self, conn, id: str, version: int, actor: Principal) -> Waiver:
        w = self.read(conn, "waivers", id, actor)
        if w.version != version:
            raise Conflict("stale version: reload before changing this waiver")
        return w

    def _save(self, conn, actor, w, action):
        values = w.model_dump()
        values.update(version=w.version + 1, updated_at=utcnow())
        w = Waiver.model_validate(values)
        self.store.save(conn, "waivers", w, actor.name, action)
        return w

    def import_run(self, actor: Principal, *, content: str, format: str, scope: Scope,
                   revision: str, complete: bool = False, checked_categories: list | None = None,
                   tool_version: str = "", rule_deck_digest: str = "", configuration_digest: str = "",
                   source_root: Path | None = None, allow_plugins: bool = False,
                   context_manifest: dict | None = None) -> Run:
        self.role(actor, "contributor", "reviewer", "admin")
        scope = Scope.model_validate(scope)
        self.project(actor, scope.project)
        if format in ("verilator", "klayout") and scope.tool.lower() != format:
            raise OpenWaiverError("native adapter and tool namespace disagree")
        if format == "sarif":
            doc = strict_json(content)
            runs = doc.get("runs", [])
            if len(runs) == 1 and runs[0].get("tool", {}).get("driver", {}).get("name") != scope.tool:
                raise OpenWaiverError("SARIF driver name and tool namespace disagree")
        violations = parse_report(content, format, source_root=source_root, allow_plugins=allow_plugins)
        if context_manifest is not None:
            from .context import ContextManifest, bind_context
            if source_root is not None:
                raise OpenWaiverError("choose source-root windows OR explicit dependency evidence, not both")
            violations = bind_context(violations, ContextManifest.model_validate(context_manifest), scope, revision)
        run = Run(scope=scope, revision=revision, complete=complete,
                  checked_categories=checked_categories or [], source_sha256=hashlib.sha256(content.encode()).hexdigest(),
                  format=format, tool_version=tool_version, rule_deck_digest=rule_deck_digest,
                  configuration_digest=configuration_digest, violations=violations)
        with self.store.transaction() as conn:
            self.store.verify(conn)
            self.store.save(conn, "runs", run, actor.name, "import", create=True)
        return run

    def propose(self, actor: Principal, *, run_id: str, violation_id: str, rationale: str,
                owner: str, reviewers: list[str], expires_on: date | None = None,
                valid_revision: str | None = None, tags: list[str] | None = None) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        if actor.role != "admin" and owner != actor.name:
            raise Forbidden("contributors must own their proposals")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            run = self.read(conn, "runs", run_id, actor)
            target = next((v for v in run.violations if v.id == violation_id), None)
            if target is None:
                raise OpenWaiverError("violation is not in the selected run")
            w = Waiver(scope=run.scope, baseline_run_id=run.id, baseline_revision=run.revision,
                       baseline_provenance=provenance(run), target=target, fingerprint=fingerprint(target),
                       rationale=rationale, owner=owner, reviewers=reviewers, expires_on=expires_on,
                       valid_revision=valid_revision, creator=actor.name, tags=tags or [])
            if any(x.scope == w.scope and x.fingerprint == w.fingerprint and x.status != "revoked"
                   for x in self.store.all(conn, "waivers")):
                raise Conflict("a non-revoked waiver already targets this identity")
            self._check_bounds(w, self.store.policy(conn))
            self.store.save(conn, "waivers", w, actor.name, "propose", create=True)
        return w

    @staticmethod
    def _check_bounds(w: Waiver, policy: Policy):
        if w.expires_on and w.expires_on < utcnow().date():
            raise OpenWaiverError("expiration is already in the past")
        if w.expires_on and (w.expires_on - w.created_at.date()).days > policy.max_waiver_days:
            raise OpenWaiverError("expiration exceeds policy horizon")
        if len(w.reviewers) < policy.quorum(w):
            raise OpenWaiverError("not enough independent reviewers for the risk-based quorum")
        if w.target.rule in policy.forbidden_rules:
            raise Forbidden("policy prohibits waiving this rule")
        if w.valid_revision and w.valid_revision != w.baseline_revision:
            raise OpenWaiverError("revision-bound waiver must name its exact baseline revision")

    def amend(self, actor: Principal, id: str, version: int, changes: dict) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        allowed = {"rationale", "owner", "reviewers", "expires_on", "valid_revision", "tags"}
        if not changes or set(changes) - allowed:
            raise OpenWaiverError("unsupported or empty amendment")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            self.owner(actor, w)
            if w.status == "revoked":
                raise Conflict("revocation is terminal; create a new proposal")
            data = {**w.model_dump(), **changes, "status": "proposed", "approvals": []}
            w = Waiver.model_validate(data)
            self._check_bounds(w, self.store.policy(conn))
            return self._save(conn, actor, w, "amend:approval-reset")

    def attach(self, actor: Principal, id: str, version: int, filename: str, content: bytes) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        if len(content) > 5 * 1024 * 1024:
            raise OpenWaiverError("attachment exceeds 5 MiB")
        if not re.fullmatch(r"[\w .()-]{1,200}", filename) or filename.startswith("."):
            raise OpenWaiverError("unsafe attachment filename")
        extension = Path(filename).suffix.lower()
        types = {".txt": "text/plain", ".json": "application/json", ".pdf": "application/pdf",
                 ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}
        if extension not in types:
            raise OpenWaiverError("accepted evidence: TXT, JSON, PDF, PNG or JPEG")
        if extension in (".txt", ".json"):
            content.decode("utf-8")
        signatures = {".png": b"\x89PNG\r\n\x1a\n", ".pdf": b"%PDF-", ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff"}
        if extension in signatures and not content.startswith(signatures[extension]):
            raise OpenWaiverError("file signature does not match extension")
        sha = hashlib.sha256(content).hexdigest()
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            self.owner(actor, w)
            if w.status not in ("proposed", "rejected"):
                raise Conflict("amend the waiver before changing evidence on a submitted/approved record")
            if any(x.sha256 == sha for x in w.evidence):
                raise Conflict("evidence is already attached")
            if len(w.evidence) >= 50:
                raise OpenWaiverError("attachment count limit reached")
            if conn.execute("SELECT 1 FROM evidence WHERE sha256=?", (sha,)).fetchone() is None:
                conn.execute("INSERT INTO evidence VALUES (?,?)", (sha, content))
                self.store.event(conn, actor.name, "attach", "evidence", sha, sha)
            w.evidence.append(Evidence(sha256=sha, filename=filename, size=len(content), media_type=types[extension]))
            w.status = "proposed"
            w.approvals = []
            return self._save(conn, actor, w, "evidence:approval-reset")

    def submit(self, actor: Principal, id: str, version: int) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            self.owner(actor, w)
            if w.status not in ("proposed", "rejected"):
                raise Conflict("only proposals or rejected records can be submitted")
            policy = self.store.policy(conn)
            self._check_bounds(w, policy)
            problems = approval_problems(w, policy, utcnow().date())
            if problems:
                raise OpenWaiverError("; ".join(problems))
            w.status, w.approvals = "submitted", []
            return self._save(conn, actor, w, "submit")

    def review(self, actor: Principal, id: str, version: int, decision: str, comment: str) -> Waiver:
        self.role(actor, "reviewer", "admin")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            if actor.name not in w.reviewers or actor.name in (w.owner, w.creator):
                raise Forbidden("only an assigned independent reviewer may decide")
            if w.status != "submitted":
                raise Conflict("review requires a submitted waiver")
            if any(a.actor == actor.name for a in w.approvals):
                raise Conflict("reviewer has already decided on this content")
            policy = self.store.policy(conn)
            problems = approval_problems(w, policy, utcnow().date())
            if problems:
                raise OpenWaiverError("; ".join(problems))
            a = Approval(actor=actor.name, decision=decision, comment=comment, content_digest=approval_digest(w))
            w.approvals.append(a)
            if decision == "reject":
                w.status = "rejected"
            elif len(w.approvals) >= policy.quorum(w):
                w.status = "approved"
            return self._save(conn, actor, w, decision)

    def revoke(self, actor: Principal, id: str, version: int, comment: str) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        if len(comment.strip()) < 3:
            raise OpenWaiverError("revocation reason required")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            if actor.name not in [w.owner, *w.reviewers] and actor.role != "admin":
                raise Forbidden("only owner, assigned reviewer or administrator can revoke")
            if w.status == "revoked":
                raise Conflict("already revoked")
            w.status = "revoked"
            w.tags = [*w.tags, "revoked"][:50]
            # Retain the reason in the signed content/audit projection, not only a UI toast.
            w.rationale = (w.rationale + "\n\nRevoked: " + comment)[:20000]
            return self._save(conn, actor, w, "revoke")

    def rebind(self, actor: Principal, id: str, version: int, run_id: str, violation_id: str) -> Waiver:
        self.role(actor, "contributor", "reviewer", "admin")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            w = self._load(conn, id, version, actor)
            self.owner(actor, w)
            if w.status == "revoked":
                raise Conflict("cannot rebind a revoked waiver")
            run = self.read(conn, "runs", run_id, actor)
            target = next((v for v in run.violations if v.id == violation_id), None)
            if target is None or run.scope != w.scope:
                raise OpenWaiverError("rebind must remain in the same project/tool/check stream")
            if (target.category, target.rule) != (w.target.category, w.target.rule):
                raise OpenWaiverError("rule or category changes require a separate proposal")
            fp = fingerprint(target)
            if any(x.id != w.id and x.scope == w.scope and x.fingerprint == fp and x.status != "revoked"
                   for x in self.store.all(conn, "waivers")):
                raise Conflict("another waiver already targets this identity")
            data = {**w.model_dump(), "baseline_run_id": run.id, "baseline_revision": run.revision,
                    "baseline_provenance": provenance(run), "target": target, "fingerprint": fp,
                    "valid_revision": run.revision if w.valid_revision else None,
                    "approvals": [], "status": "proposed"}
            # Previous evidence is retained as history, but must be reassessed by fresh reviewers.
            w = Waiver.model_validate(data)
            return self._save(conn, actor, w, "rebind:approval-reset")

    def assessment(self, run_id: str, today: date | None = None, *, actor: Principal | None = None) -> dict:
        with self.store.transaction(write=False) as conn:
            self.store.verify(conn)
            return assess(self.read(conn, "runs", run_id, actor), self.store.all(conn, "waivers"),
                          self.store.policy(conn), today or utcnow().date())

    def freeze(self, actor: Principal, run_id: str, name: str, *, require_clean: bool = False) -> Snapshot:
        self.role(actor, "reviewer", "admin")
        with self.store.transaction() as conn:
            self.store.verify(conn)
            run = self.read(conn, "runs", run_id, actor)
            policy = self.store.policy(conn)
            waivers = [w for w in self.store.all(conn, "waivers") if w.scope == run.scope]
            result = assess(run, waivers, policy, utcnow().date())
            if require_clean and not result["gate_pass"]:
                raise Conflict("cannot freeze as clean: gate has blockers")
            snapshot = Snapshot(name=name, actor=actor.name, run=run, policy=policy, waivers=waivers,
                                assessment=result, audit_head=self.store.head(conn))
            self.store.save(conn, "snapshots", snapshot, actor.name, "freeze", create=True)
            return snapshot

    def set_policy(self, actor: Principal, policy: Policy):
        self.role(actor, "admin")
        from .access import workspace_only
        workspace_only(actor)
        with self.store.transaction() as conn:
            self.store.verify(conn)
            conn.execute("UPDATE meta SET value=? WHERE key='policy'", (policy.model_dump_json(),))
            self.store.event(conn, actor.name, "policy-change", "policy", "policy", digest(policy))
        return policy
