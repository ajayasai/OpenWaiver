from copy import deepcopy
import hashlib
import pytest

from openwaiver.context import ContextManifest, bind_context, build_context, compare_context, safe_path
from openwaiver.models import Scope, Violation


@pytest.fixture
def context_spec(tmp_path):
    for name in ["top.sv", "defines.svh", "unrelated.sv"]:
        (tmp_path / name).write_text("synthetic source for " + name)
    return {"schema_version": 1, "scope": {"project": "chip", "stream": "nightly", "tool": "verilator"},
        "revision": "rev-a", "settings": {"defines": "SYNTHESIS=1"},
        "nodes": {"top.sv": {"dependencies": ["defines.svh"]}, "defines.svh": {}, "unrelated.sv": {}},
        "targets": {"v1": ["top.sv"], "v2": ["unrelated.sv"]}}


def test_content_changes_only_invalidate_dependent_targets(context_spec, tmp_path):
    before = build_context(tmp_path, context_spec)
    (tmp_path / "defines.svh").write_text("changed include")
    after = build_context(tmp_path, {**context_spec, "revision": "rev-b"})
    diff = compare_context(before, after)
    assert diff["content_changed"] == ["defines.svh"]
    assert diff["targets_impacted"] == ["v1"] and diff["targets_unchanged"] == ["v2"]


def test_irrelevant_revision_and_order_do_not_change_context(context_spec, tmp_path):
    a = build_context(tmp_path, context_spec)
    reordered = {**context_spec, "revision": "rev-b", "nodes": dict(reversed(list(context_spec["nodes"].items())))}
    b = build_context(tmp_path, reordered)
    assert a.context_hashes() == b.context_hashes()


def test_settings_or_graph_edges_invalidate_context(context_spec, tmp_path):
    a = build_context(tmp_path, context_spec)
    b = build_context(tmp_path, {**context_spec, "settings": {"defines": "SYNTHESIS=0"}})
    assert compare_context(a, b)["targets_impacted"] == ["v1", "v2"]
    changed = deepcopy(context_spec)
    changed["nodes"]["top.sv"]["dependencies"] = []
    c = build_context(tmp_path, changed)
    assert compare_context(a, c)["dependencies_changed"] == ["top.sv"]
    assert compare_context(a, c)["targets_impacted"] == ["v1"]


@pytest.mark.parametrize("path", ["../secret", "/absolute", "a/../b", "a//b", "./a", "a\\b", "a:", "", "a\x00"])
def test_unsafe_dependency_paths_rejected(path):
    with pytest.raises(ValueError):
        safe_path(path)


def test_missing_dependency_and_cycle_rejected(context_spec, tmp_path):
    spec = deepcopy(context_spec)
    spec["nodes"]["top.sv"]["dependencies"] = ["absent"]
    with pytest.raises(ValueError):
        build_context(tmp_path, spec)
    spec["nodes"]["top.sv"]["dependencies"] = ["defines.svh"]
    spec["nodes"]["defines.svh"]["dependencies"] = ["top.sv"]
    with pytest.raises(ValueError, match="cycle"):
        build_context(tmp_path, spec)


def test_symlink_rejected(context_spec, tmp_path):
    (tmp_path / "top.sv").unlink()
    (tmp_path / "top.sv").symlink_to(tmp_path / "defines.svh")
    with pytest.raises(ValueError, match="symlink"):
        build_context(tmp_path, context_spec)


def test_iterative_hashing_handles_deep_graph():
    n = 2500
    spec = {"scope": {"project": "p", "stream": "s", "tool": "t"}, "revision": "r",
        "nodes": {f"f{i}": {"sha256": "a" * 64, "dependencies": [f"f{i-1}"] if i else []} for i in range(n)},
        "targets": {"v": [f"f{n-1}"]}}
    assert len(ContextManifest.model_validate(spec).context_hashes()["v"]) == 64


def test_import_uses_real_dependency_hash_and_stales_approval(service, actors, make_run, make_waiver, record, context_spec, tmp_path):
    spec = {**context_spec, "targets": {"v1": ["top.sv"]}}
    manifest = build_context(tmp_path, spec)
    report = {**record, "context_hash": ""}
    a = make_run([report], context_manifest=manifest.model_dump(mode="json"))
    make_waiver(a)
    spec["revision"] = "rev-b"
    unchanged = build_context(tmp_path, spec)
    b = make_run([report], revision="rev-b", context_manifest=unchanged.model_dump(mode="json"))
    assert service.assessment(b.id)["gate_pass"]
    (tmp_path / "defines.svh").write_text("changed transitive dependency")
    changed = build_context(tmp_path, spec)
    c = make_run([report], revision="rev-b", context_manifest=changed.model_dump(mode="json"))
    assert service.assessment(c.id)["counts"] == {"stale": 1}


def test_manifest_scope_revision_coverage_and_claim_checked(context_spec, tmp_path, record):
    manifest = build_context(tmp_path, {**context_spec, "targets": {"v1": ["top.sv"]}})
    violation = Violation.model_validate({**record, "context_hash": ""})
    with pytest.raises(ValueError):
        bind_context([violation], manifest, manifest.scope, "wrong-revision")
    with pytest.raises(ValueError):
        bind_context([], manifest, manifest.scope, manifest.revision)
    with pytest.raises(ValueError):
        bind_context([Violation.model_validate(record)], manifest, manifest.scope, manifest.revision)
    result = bind_context([violation], manifest, manifest.scope, manifest.revision)
    assert result[0].context_hash == manifest.context_hashes()["v1"]
