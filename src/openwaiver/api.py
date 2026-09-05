"""Authenticated local-first API. Bearer identity comes ONLY from the server's token registry."""
from __future__ import annotations

import base64
import binascii
from datetime import date
import hashlib
import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import Field

from . import __version__
from .engine import compare_snapshots
from .errors import Conflict, Forbidden, IntegrityError, NotFound, OpenWaiverError
from .exporters import export_report
from .importers import MAX_REPORT_BYTES, strict_json
from .interchange import bundle
from .models import Model, Policy, Principal, Scope
from .release import ReleaseManifest, gate_release
from .service import Service
from .store import Store


class ImportRequest(Model):
    content: str = Field(max_length=MAX_REPORT_BYTES)
    format: str
    scope: Scope
    revision: str
    complete: bool = False
    checked_categories: list[str] = Field(default_factory=list)
    tool_version: str = ""
    rule_deck_digest: str = ""
    configuration_digest: str = ""


class Proposal(Model):
    run_id: str
    violation_id: str
    rationale: str
    owner: str
    reviewers: list[str]
    expires_on: date | None = None
    valid_revision: str | None = None
    tags: list[str] = Field(default_factory=list)


class Version(Model):
    version: int = Field(ge=1)


class Review(Version):
    decision: str
    comment: str


class Amend(Version):
    changes: dict


class Rebind(Version):
    run_id: str
    violation_id: str


class Revoke(Version):
    comment: str


class Attachment(Version):
    filename: str
    content_base64: str = Field(max_length=7 * 1024 * 1024)


class Freeze(Model):
    run_id: str
    name: str
    require_clean: bool = False


class BodyLimit:
    def __init__(self, app, max_bytes=MAX_REPORT_BYTES + 1024 * 1024):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        payload = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            payload.extend(message.get("body", b""))
            if len(payload) > self.max_bytes:
                await JSONResponse({"detail": "request body limit exceeded"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        sent = False

        async def bounded_receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": bytes(payload), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


def token_records(path: Path) -> list[dict]:
    doc = strict_json(path.read_text(encoding="utf-8"))
    records = doc.get("tokens", [])
    if not records:
        raise OpenWaiverError("authentication registry must contain at least one token")
    seen = set()
    for record in records:
        Principal(name=record["name"], role=record["role"])
        sha = record["sha256"]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha) or sha in seen:
            raise OpenWaiverError("invalid or duplicate token digest")
        seen.add(sha)
    return records


def create_app(db_path: str | Path | None = None, auth: list[dict] | None = None) -> FastAPI:
    if auth is None:
        registry = os.environ.get("OPENWAIVER_AUTH_FILE")
        if not registry:
            raise OpenWaiverError("OPENWAIVER_AUTH_FILE is required; use openwaiver auth-create")
        auth = token_records(Path(registry))
    if not auth:
        raise OpenWaiverError("refusing to start without authentication")
    service = Service(Store(db_path or os.environ.get("OPENWAIVER_DB", "workspace/openwaiver.sqlite3")))
    app = FastAPI(title="OpenWaiver", version=__version__, description="Cross-tool waiver lifecycle API")
    app.state.service = service
    app.add_middleware(BodyLimit)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=os.environ.get(
        "OPENWAIVER_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver").split(","))
    bearer = HTTPBearer(auto_error=False)

    def principal(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if credentials is None:
            raise HTTPException(401, "bearer token required", headers={"WWW-Authenticate": "Bearer"})
        candidate = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        match = None
        for record in auth:
            if hmac.compare_digest(candidate, record["sha256"]):
                match = record
        if match is None:
            raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        return Principal(name=match["name"], role=match["role"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        origin = request.headers.get("origin")
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and origin:
            if origin not in (f"http://{request.url.netloc}", f"https://{request.url.netloc}"):
                return JSONResponse({"detail": "cross-origin write rejected"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return response

    @app.exception_handler(OpenWaiverError)
    async def domain_error(request, exc):
        code = (409 if isinstance(exc, Conflict) else 403 if isinstance(exc, Forbidden)
                else 404 if isinstance(exc, NotFound) else 503 if isinstance(exc, IntegrityError) else 400)
        return JSONResponse({"detail": str(exc)}, status_code=code)

    @app.exception_handler(ValueError)
    async def input_error(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=400)

    @app.get("/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.post("/api/release-gate")
    def release_gate(body: ReleaseManifest, actor: Principal = Depends(principal)):
        return gate_release(service.store, body)

    @app.get("/api/me")
    def me(actor: Principal = Depends(principal)):
        return actor

    @app.get("/api/runs")
    def runs(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
             actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            items = list(reversed(service.store.all(conn, "runs")))
            return {"total": len(items), "items": [{**x.model_dump(mode="json", exclude={"violations"}),
                     "violation_count": len(x.violations)} for x in items[offset:offset + limit]]}

    @app.post("/api/runs", status_code=201)
    def import_run(body: ImportRequest, actor: Principal = Depends(principal)):
        return service.import_run(actor, **body.model_dump())

    @app.get("/api/runs/{id}/assessment")
    def assessment(id: str, offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                   q: str = "", status: str = "", category: str = "", actor: Principal = Depends(principal)):
        result = service.assessment(id)
        rows = result["violations"]
        if status:
            rows = [r for r in rows if r["status"] == status]
        if category:
            rows = [r for r in rows if r["violation"]["category"] == category]
        if q:
            q = q.casefold()
            rows = [r for r in rows if q in " ".join(str(v) for v in r["violation"].values()).casefold()]
        return {**result, "violations": rows[offset:offset + limit], "total": len(rows), "offset": offset}

    @app.get("/api/waivers")
    def waivers(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            items = list(reversed(service.store.all(conn, "waivers")))
            return {"items": items[offset:offset + limit], "total": len(items)}

    @app.get("/api/waivers/{id}")
    def waiver(id: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            return service.store.get(conn, "waivers", id)

    @app.get("/api/waivers/{id}/history")
    def history(id: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            service.store.get(conn, "waivers", id)
            return [e for e in service.store.events(conn) if e["entity"] == "waivers" and e["id"] == id]

    @app.post("/api/waivers", status_code=201)
    def propose(body: Proposal, actor: Principal = Depends(principal)):
        return service.propose(actor, **body.model_dump())

    @app.post("/api/waivers/{id}/submit")
    def submit(id: str, body: Version, actor: Principal = Depends(principal)):
        return service.submit(actor, id, body.version)

    @app.post("/api/waivers/{id}/review")
    def review(id: str, body: Review, actor: Principal = Depends(principal)):
        return service.review(actor, id, **body.model_dump())

    @app.post("/api/waivers/{id}/amend")
    def amend(id: str, body: Amend, actor: Principal = Depends(principal)):
        return service.amend(actor, id, **body.model_dump())

    @app.post("/api/waivers/{id}/rebind")
    def rebind(id: str, body: Rebind, actor: Principal = Depends(principal)):
        return service.rebind(actor, id, **body.model_dump())

    @app.post("/api/waivers/{id}/revoke")
    def revoke(id: str, body: Revoke, actor: Principal = Depends(principal)):
        return service.revoke(actor, id, **body.model_dump())

    @app.post("/api/waivers/{id}/evidence")
    def evidence(id: str, body: Attachment, actor: Principal = Depends(principal)):
        try:
            content = base64.b64decode(body.content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise OpenWaiverError("invalid base64 attachment") from exc
        return service.attach(actor, id, body.version, body.filename, content)

    @app.get("/api/evidence/{sha}")
    def download_evidence(sha: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            service.store.verify(conn)
            row = conn.execute("SELECT data FROM evidence WHERE sha256=?", (sha,)).fetchone()
            if row is None:
                raise NotFound("evidence not found")
            return Response(row[0], media_type="application/octet-stream",
                            headers={"Content-Disposition": 'attachment; filename="evidence.bin"'})

    @app.get("/api/audit")
    def audit(limit: int = Query(50, ge=1, le=500), actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            verified = service.store.verify(conn)
            events = service.store.events(conn)[-limit:][::-1]
            return {**verified, "events": [{k: v for k, v in x.items() if k != "record"} for x in events]}

    @app.get("/api/policy")
    def policy(actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            return service.store.policy(conn)

    @app.put("/api/policy")
    def set_policy(body: Policy, actor: Principal = Depends(principal)):
        return service.set_policy(actor, body)

    @app.get("/api/snapshots")
    def snapshots(actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            return [{"id": s.id, "name": s.name, "created_at": s.created_at, "revision": s.run.revision,
                     "gate_pass": s.assessment["gate_pass"], "run_id": s.run.id}
                    for s in reversed(service.store.all(conn, "snapshots"))]

    @app.post("/api/snapshots", status_code=201)
    def freeze(body: Freeze, actor: Principal = Depends(principal)):
        return service.freeze(actor, body.run_id, body.name, require_clean=body.require_clean)

    @app.get("/api/snapshots/{id}/bundle")
    def get_bundle(id: str, actor: Principal = Depends(principal)):
        return Response(bundle(service, id), media_type="application/zip",
                        headers={"Content-Disposition": 'attachment; filename="openwaiver-evidence.zip"'})

    @app.get("/api/compare/{before}/{after}")
    def compare(before: str, after: str, actor: Principal = Depends(principal)):
        with service.store.transaction(write=False) as conn:
            service.store.verify(conn)
            return compare_snapshots(service.store.get(conn, "snapshots", before),
                                     service.store.get(conn, "snapshots", after))

    @app.get("/api/runs/{id}/export/{format}")
    def export(id: str, format: str, acknowledge_lossy: bool = False, actor: Principal = Depends(principal)):
        data = export_report(service.assessment(id), format, acknowledge_lossy=acknowledge_lossy)
        extensions = {"json": "json", "sarif": "sarif", "html": "html", "junit": "xml", "verilator": "vlt"}
        return Response(data, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="assessment.{extensions[format]}"'})

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    return app
