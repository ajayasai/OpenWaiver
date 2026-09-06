"""Optional KLayout-native extraction from GDS/OASIS, without executing input scripts.

Only unit-scale orthogonal placements and polygon/box geometry are accepted. Text,
paths, complex transforms and ambiguous replicated marker cells fail explicitly.
Run native parsers in a resource-limited worker for untrusted layout files.
"""
from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
import hashlib
from importlib.metadata import version
from pathlib import Path
import re

from .errors import OpenWaiverError
from .identity import canonical
from .importers import parse_report
from .models import Scope
from .physical import (MAX_VERTICES, Neighborhood, PhysicalManifest, Placement, Polygon,
                       Recipe, bind_physical, marker, window)


def _placement(t) -> Placement:
    if t.mag != 1 or t.angle not in (0, 90, 180, 270):
        raise OpenWaiverError("non-orthogonal or magnified hierarchy would require rounding; rejected")
    return Placement(rotation=int(t.angle), mirror=t.is_mirror(), dx=t.disp.x, dy=t.disp.y)


def _instances(layout, top, db):
    """Resolve all actual placements, retaining coincident duplicates as ambiguous."""
    places = defaultdict(list)
    stack = [(top, db.ICplxTrans(), ())]
    count = 0
    while stack:
        cell, transform, ancestors = stack.pop()
        index = cell.cell_index()
        if index in ancestors or len(ancestors) > 128:
            raise OpenWaiverError("cyclic or over-deep layout hierarchy")
        count += 1
        if count > 100000:
            raise OpenWaiverError("instance expansion budget exceeded")
        places[cell.name].append(_placement(transform))
        for instance in cell.each_inst():
            for local in instance.cell_inst.each_cplx_trans():
                _placement(local)  # Reject rounding at every hierarchy level.
                stack.append((layout.cell(instance.cell_index), transform * local, ancestors + (index,)))
                if len(stack) + count > 100000:
                    raise OpenWaiverError("instance expansion budget exceeded")
    return places


def extract_layout(*, layout_path: Path, content: str, format: str, scope: Scope,
                   revision: str, top_cell: str, layers: list[str], halo_dbu: int,
                   placements: dict[str, dict] | None = None) -> PhysicalManifest:
    try:
        import klayout.db as db
    except ImportError as exc:
        raise OpenWaiverError("install openwaiver[physical] to enable the native layout reader") from exc
    recipe = Recipe(top_cell=top_cell, dbu_nm="1", layers=layers, halo_dbu=halo_dbu,
                    producer="klayout-python/" + version("klayout"))
    layer_numbers = []
    for layer in layers:
        if not re.fullmatch(r"\d{1,5}/\d{1,5}", layer):
            raise OpenWaiverError("native layers must use explicit layer/datatype identifiers")
        values = tuple(map(int, layer.split("/")))
        if any(x > 65535 for x in values) or layer != f"{values[0]}/{values[1]}":
            raise OpenWaiverError("noncanonical native layer identifier")
        layer_numbers.append(values)
    path = Path(layout_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise OpenWaiverError("layout must be a regular, non-symlink file of at most 256 MiB")
    with path.open("rb") as source:
        data = source.read(256 * 1024 * 1024 + 1)
    if len(data) > 256 * 1024 * 1024:
        raise OpenWaiverError("layout byte budget exceeded")
    # Read the exact hashed bytes through a private copy to avoid layout/hash TOCTOU.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="openwaiver-layout-") as directory:
        copy = Path(directory) / ("input" + path.suffix)
        copy.write_bytes(data)
        layout = db.Layout()
        layout.read(str(copy))
    top = layout.cell(top_cell)
    if top is None:
        raise OpenWaiverError("declared root cell is absent")
    recipe.dbu_nm = format_decimal(Decimal(str(layout.dbu)) * 1000)
    indices = []
    for layer, datatype in layer_numbers:
        index = layout.find_layer(layer, datatype)
        if index is None or index < 0:
            raise OpenWaiverError("declared layer is absent; absence is not proof of empty coverage")
        indices.append(index)
    places = _instances(layout, top, db)
    findings = parse_report(content, format)
    if len(findings) > 10000:
        raise OpenWaiverError("physical finding count budget exceeded")
    selections = placements or {}
    if set(selections) - {v.id for v in findings}:
        raise OpenWaiverError("placement selection names an unknown occurrence")
    targets, vertices = {}, 0
    for finding in findings:
        options = places.get(finding.hierarchy, [])
        if finding.id in selections:
            chosen = Placement.model_validate(selections[finding.id])
            options = [x for x in options if x == chosen]
        if len(options) != 1:
            raise OpenWaiverError("marker cell placement is absent or ambiguous; select an actual unique placement")
        placement = options[0]
        box = db.Box(*window(marker(finding, recipe, placement), halo_dbu))
        shapes = []
        for name, index in zip(layers, indices):
            iterator = top.begin_shapes_rec_touching(index, box)
            while not iterator.at_end():
                shape, transform = iterator.shape(), iterator.trans()
                _placement(transform)
                if not (shape.is_box() or shape.is_polygon() or shape.is_simple_polygon()):
                    raise OpenWaiverError("unsupported native shape in context window; no shape was silently dropped")
                polygon = shape.polygon.transformed(transform)
                hull = [(p.x, p.y) for p in polygon.each_point_hull()]
                holes = [[(p.x, p.y) for p in polygon.each_point_hole(i)] for i in range(polygon.holes())]
                vertices += len(hull) + sum(map(len, holes))
                if vertices > MAX_VERTICES or len(shapes) >= 10000:
                    raise OpenWaiverError("native context budget exceeded; no partial manifest emitted")
                props = {canonical(k): canonical(v) for k, v in shape.properties().items()}
                shapes.append(Polygon(layer=name, hull=hull, holes=holes, properties=props))
                iterator.next()
        targets[finding.id] = Neighborhood(placement=placement, shapes=shapes)
    manifest = PhysicalManifest(scope=scope, revision=revision,
        report_sha256=hashlib.sha256(content.encode()).hexdigest(), layout_sha256=hashlib.sha256(data).hexdigest(),
        recipe=recipe, targets=targets)
    bind_physical(findings, manifest, scope, revision, manifest.report_sha256)
    return manifest


def format_decimal(value: Decimal) -> str:
    return format(value, "f")
