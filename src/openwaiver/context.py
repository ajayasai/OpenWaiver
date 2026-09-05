"""Content-derived dependency-cone evidence, not guessed text windows.

A trusted build adapter supplies the explicit graph. Hashes prove only the declared
inputs: they do not prove a dependency graph is complete or an EDA run occurred.
"""
from __future__ import annotations

from collections import defaultdict, deque
import hashlib
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from .errors import OpenWaiverError
from .identity import digest
from .models import Model, Scope, Violation


def safe_path(value: str) -> str:
    if (not value or "\\" in value or ":" in value or any(ord(c) < 32 for c in value)
            or PurePosixPath(value).is_absolute() or str(PurePosixPath(value)) != value
            or any(x in (".", "..", "") for x in value.split("/"))):
        raise ValueError("dependency path must be a canonical workspace-relative POSIX path")
    return value


class DependencyNode(Model):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    dependencies: list[str] = Field(default_factory=list, max_length=10000)


class ContextManifest(Model):
    schema_version: Literal[1] = 1
    scope: Scope
    revision: str = Field(min_length=1)
    # Settings must include semantic build inputs (defines, include order, corners).
    settings: dict[str, str] = Field(default_factory=dict, max_length=10000)
    nodes: dict[str, DependencyNode] = Field(min_length=1, max_length=100000)
    targets: dict[str, list[str]] = Field(min_length=1, max_length=250000)

    @model_validator(mode="after")
    def graph(self):
        for name, node in self.nodes.items():
            safe_path(name)
            if len(node.dependencies) != len(set(node.dependencies)):
                raise ValueError("duplicate dependency")
            if any(dep not in self.nodes for dep in node.dependencies):
                raise ValueError("dependency references a missing node")
        for marker, roots in self.targets.items():
            if not marker or not roots or len(roots) != len(set(roots)):
                raise ValueError("each target needs distinct nonempty dependency roots")
            if any(root not in self.nodes for root in roots):
                raise ValueError("target references a missing node")
        self.node_hashes()  # Also rejects cycles without recursive Python calls.
        return self

    def node_hashes(self) -> dict[str, str]:
        parents = defaultdict(list)
        degree = {}
        for path, node in self.nodes.items():
            degree[path] = len(node.dependencies)
            for dep in node.dependencies:
                parents[dep].append(path)
        ready = deque(path for path, size in degree.items() if size == 0)
        hashed = {}
        while ready:
            path = ready.popleft()
            node = self.nodes[path]
            hashed[path] = digest({"domain": "openwaiver.dependency.v1", "path": path,
                "sha256": node.sha256,
                "dependencies": {d: hashed[d] for d in sorted(node.dependencies)}})
            for parent in parents[path]:
                degree[parent] -= 1
                if degree[parent] == 0:
                    ready.append(parent)
        if len(hashed) != len(self.nodes):
            raise ValueError("dependency graph contains a cycle")
        return hashed

    def context_hashes(self) -> dict[str, str]:
        hashed = self.node_hashes()
        return {marker: digest({"domain": "openwaiver.context.v1", "scope": self.scope.model_dump(),
                "settings": self.settings, "roots": {r: hashed[r] for r in sorted(roots)}})
                for marker, roots in self.targets.items()}


def bind_context(violations: list[Violation], manifest: ContextManifest, scope: Scope,
                 revision: str) -> list[Violation]:
    if manifest.scope != scope or manifest.revision != revision:
        raise OpenWaiverError("context manifest project/tool/stream or revision does not match the run")
    if set(manifest.targets) != {v.id for v in violations}:
        raise OpenWaiverError("context manifest must cover exactly every imported occurrence ID")
    hashes = manifest.context_hashes()
    result = []
    for v in violations:
        if v.context_hash and v.context_hash != hashes[v.id]:
            raise OpenWaiverError("report context hash disagrees with computed dependency evidence")
        result.append(Violation.model_validate({**v.model_dump(), "context_hash": hashes[v.id]}))
    return result


def build_context(root: Path, specification: dict) -> ContextManifest:
    """Replace each declared node's hash with actual local bytes; no filesystem discovery.

    Input uses the ContextManifest shape, but each node only supplies dependencies.
    Run against an immutable checkout: local filesystem operators remain trusted.
    """
    root = root.resolve(strict=True)
    if not isinstance(specification, dict) or not isinstance(specification.get("nodes"), dict):
        raise OpenWaiverError("dependency specification must contain a nodes mapping")
    spec = dict(specification)
    if any(not isinstance(node, dict) for node in spec["nodes"].values()):
        raise OpenWaiverError("each dependency node must be a mapping")
    # Validate schema, graph and resource counts before touching any dependency file.
    checked = ContextManifest.model_validate({**spec, "nodes": {
        name: {**node, "sha256": "0" * 64} for name, node in spec["nodes"].items()}})
    nodes, total = {}, 0
    for name, checked_node in checked.nodes.items():
        node = checked_node.model_dump()
        safe_path(name)
        path = root
        for component in name.split("/"):
            path = path / component
            if path.is_symlink():
                raise OpenWaiverError("symlink dependency rejected")
        if not path.is_file() or not path.resolve().is_relative_to(root):
            raise OpenWaiverError("dependency is missing or outside workspace")
        h, count = hashlib.sha256(), 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                count += len(chunk)
                total += len(chunk)
                if count > 64 * 1024 * 1024 or total > 512 * 1024 * 1024:
                    raise OpenWaiverError("dependency input byte budget exceeded")
                h.update(chunk)
        nodes[name] = {**node, "sha256": h.hexdigest()}
    spec["nodes"] = nodes
    return ContextManifest.model_validate(spec)


def compare_context(before: ContextManifest, after: ContextManifest) -> dict:
    if before.scope != after.scope:
        raise OpenWaiverError("cannot compare dependency evidence across different scopes")
    old, new = before.context_hashes(), after.context_hashes()
    common = before.nodes.keys() & after.nodes.keys()
    return {"before_revision": before.revision, "after_revision": after.revision,
            "files_added": sorted(after.nodes.keys() - before.nodes.keys()),
            "files_removed": sorted(before.nodes.keys() - after.nodes.keys()),
            "content_changed": sorted(p for p in common if before.nodes[p].sha256 != after.nodes[p].sha256),
            "dependencies_changed": sorted(p for p in common if set(before.nodes[p].dependencies) != set(after.nodes[p].dependencies)),
            "settings_changed": before.settings != after.settings,
            "targets_impacted": sorted(k for k in old.keys() | new.keys() if old.get(k) != new.get(k)),
            "targets_unchanged": sorted(k for k in old.keys() & new.keys() if old[k] == new[k]),
            "before_sha256": digest(before), "after_sha256": digest(after)}
