"""One-use, hash-guarded source upgrade from reviewed v0.2 files. No network access."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]


def patch(path, expected, replacements):
    p = ROOT / path
    raw = p.read_bytes()
    git_hash = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if expected and git_hash != expected:
        raise RuntimeError(f"upstream changed: {path}: {git_hash}")
    text = raw.decode()
    for old, new in replacements:
        if text.count(old) != 1:
            raise RuntimeError(f"expected exactly one patch anchor in {path}: {old[:80]!r}")
        text = text.replace(old, new, 1)
    p.write_text(text)


MODEL_PATCH = [
    ("Field, field_validator, model_validator", "Field, field_validator, model_validator, model_serializer"),
    ("    violations: list[Violation] = Field(default_factory=list, max_length=250000)\n", '''    violations: list[Violation] = Field(default_factory=list, max_length=250000)
    physical_manifest: dict | None = None

    @model_serializer(mode="wrap")
    def compatible_dump(self, handler):
        data = handler(self)
        if self.physical_manifest is None:
            data.pop("physical_manifest", None)
        return data

    @model_validator(mode="after")
    def physical_binding(self):
        from .physical import validate_run
        validate_run(self)
        return self
''')]

SERVICE_PATCH = [
    ("                   context_manifest: dict | None = None) -> Run:",
     "                   context_manifest: dict | None = None, physical_manifest: dict | None = None) -> Run:"),
    ("        run = Run(scope=scope, revision=revision, complete=complete,", '''        if physical_manifest is not None:
            from .physical import PhysicalManifest, bind_physical
            if context_manifest is not None or source_root is not None:
                raise OpenWaiverError("physical evidence cannot be combined with another context source")
            physical = PhysicalManifest.model_validate(physical_manifest)
            violations = bind_physical(violations, physical, scope, revision,
                                       hashlib.sha256(content.encode()).hexdigest())
            physical_manifest = physical.model_dump(mode="json")
        run = Run(scope=scope, revision=revision, complete=complete,'''),
    ("configuration_digest=configuration_digest, violations=violations)",
     "configuration_digest=configuration_digest, violations=violations, physical_manifest=physical_manifest)")]

API_PATCH = [
    ("    context_manifest: dict | None = None\n", "    context_manifest: dict | None = None\n    physical_manifest: dict | None = None\n"),
    ("def create_app(db_path: str | Path | None = None, auth: list[dict] | None = None, *, auth_file: str | Path | None = None) -> FastAPI:\n",
     '''def create_app(db_path: str | Path | None = None, auth: list[dict] | None = None, *,
               auth_file: str | Path | None = None, federation_file: str | Path | None = None) -> FastAPI:
    from .federation import load_config, validate_access_token, InvalidAccessToken, FederationUnavailable
    federation_file = federation_file or os.environ.get("OPENWAIVER_FEDERATION_FILE")
    if federation_file:
        load_config(federation_file)  # Invalid trust configuration prevents startup.
'''),
    ('''        if not registry:
            raise OpenWaiverError("OPENWAIVER_AUTH_FILE is required; use openwaiver auth-create")
        auth_file = Path(registry)
        auth = token_records(auth_file)
    if not auth:
        raise OpenWaiverError("refusing to start without authentication")
    validate_records(auth)
''', '''        if registry:
            auth_file = Path(registry)
            auth = token_records(auth_file)
        elif federation_file:
            auth = []
        else:
            raise OpenWaiverError("OPENWAIVER_AUTH_FILE or OPENWAIVER_FEDERATION_FILE is required")
    if not auth and not federation_file:
        raise OpenWaiverError("refusing to start without authentication")
    if auth:
        validate_records(auth)
'''),
    ("        candidate = hashlib.sha256(credentials.credentials.encode()).hexdigest()", '''        if federation_file and credentials.credentials.count(".") == 2:
            try:
                return validate_access_token(credentials.credentials, load_config(federation_file))
            except FederationUnavailable:
                raise HTTPException(503, "federation trust configuration unavailable") from None
            except InvalidAccessToken:
                raise HTTPException(401, "invalid access token", headers={"WWW-Authenticate": "Bearer"}) from None
        if not auth and not auth_file:
            raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
        candidate = hashlib.sha256(credentials.credentials.encode()).hexdigest()'''),
    ('exclude={"violations"}', 'exclude={"violations", "physical_manifest"}'),
    ("    register_routes(app, service, principal)\n", '''    register_routes(app, service, principal)
    from .physical_routes import register_physical_routes
    register_physical_routes(app, service, principal)
''')]


def main():
    patch("src/openwaiver/models.py", "66e00c14a45c07c631d5b2be5baff7fb66b42503", MODEL_PATCH)
    patch("src/openwaiver/service.py", "2cb7dfc590dced126b8bbb11ef964ad28a88c97f", SERVICE_PATCH)
    patch("src/openwaiver/api.py", "1249c690be8854898e4c209c21d2c59df3d888fd", API_PATCH)
    patch("pyproject.toml", "f2823f68b29b1b33c1a410f76f8517e95981b5e7", [
        ('version = "0.2.0"', 'version = "0.3.0"'),
        ('"cryptography>=44,<52"', '"cryptography>=44,<52", "PyJWT>=2.10,<3"'),
        ('browser = ["playwright>=1.50,<2"]', 'browser = ["playwright>=1.50,<2"]\nphysical = ["klayout>=0.30,<0.31"]'),
        ('openwaiver = "openwaiver.cli:main"', 'openwaiver = "openwaiver.cli:main"\nopenwaiver-physical = "openwaiver.physical_cli:main"')])
    patch("src/openwaiver/__init__.py", None, [('"0.2.0"', '"0.3.0"')])
    patch("CHANGELOG.md", None, [("# Changelog\n", "# Changelog\n\n## 0.3.0 — 2026-09-06\n\nRetained, report-bound physical context; native GDS/OASIS extraction through KLayout; orthogonal whole-neighborhood comparisons; read-only before/after geometry workspace; explicit physical CLI; pinned-key federated JWT access-token validation and project mapping. Changed context blocks approval reuse. Existing record serialization is preserved when physical evidence is absent. Qualification remains version/fixture-specific.\n")])
    # The standalone physical CLI imports through Service; no existing CLI syntax is removed.
    patch("README.md", None, [("# OpenWaiver\n", '''# OpenWaiver

**v0.3 upgrade:** [Physical layout context and federated access-token authentication](docs/V0.3.md).
Native GDS/OASIS extraction retains polygon holes and hierarchy placements. The
[physical review workspace](http://127.0.0.1:8765/physical) visualizes retained evidence;
transform matches never approve waivers. Existing v0.2 records remain readable.

'''), ('**Version 0.2.0', '**Version 0.3.0')])


if __name__ == "__main__":
    main()
