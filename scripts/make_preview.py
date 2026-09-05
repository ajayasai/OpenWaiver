#!/usr/bin/env python3
"""Build a self-contained read-only HTML preview from a freshly seeded synthetic database."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from openwaiver.demo import seed
from openwaiver.engine import compare_snapshots
from openwaiver.exporters import export_report
from openwaiver.service import Service
from openwaiver.store import Store


def make(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix='openwaiver-preview-') as temp:
        db = Path(temp) / 'demo.sqlite3'
        seed(db)
        service = Service(Store(db))
        with service.store.transaction(write=False) as conn:
            runs = list(reversed(service.store.all(conn, 'runs')))
            waivers = list(reversed(service.store.all(conn, 'waivers')))
            snapshots = list(reversed(service.store.all(conn, 'snapshots')))
            events = service.store.events(conn)
            audit = service.store.verify(conn)
            data = {
                'runs': [{**r.model_dump(mode='json', exclude={'violations'}), 'violation_count': len(r.violations)} for r in runs],
                'waivers': [w.model_dump(mode='json') for w in waivers],
                'snapshots': [{'id': s.id, 'name': s.name, 'revision': s.run.revision, 'run_id': s.run.id,
                               'created_at': s.created_at.isoformat(), 'gate_pass': s.assessment['gate_pass']} for s in snapshots],
                'policy': service.store.policy(conn).model_dump(mode='json'),
                'audit': {**audit, 'events': [{k:v for k,v in e.items() if k!='record'} for e in reversed(events[-50:])]},
                'history': {w.id: [e for e in events if e['entity']=='waivers' and e['id']==w.id] for w in waivers},
                'comparisons': {f'{a.id}/{b.id}': compare_snapshots(a,b) for a in snapshots for b in snapshots},
            }
        data['assessments'] = {r.id: service.assessment(r.id) for r in runs}
        data['exports'] = {r.id: {fmt: export_report(data['assessments'][r.id],fmt) for fmt in ['json','sarif','html','junit']} for r in runs}
        static = ROOT / 'src/openwaiver/static'
        html = (static/'index.html').read_text()
        html = html.replace('<link rel="stylesheet" href="/static/style.css">', '<style>'+ (static/'style.css').read_text() +'</style>')
        html = html.replace('<script src="/static/app.js" defer></script>','')
        html = html.replace('<script src="/static/plans.js" defer></script>','')
        # Prevent data containing a closing script tag from escaping the JSON script assignment.
        payload = json.dumps(data, ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
        html = html.replace('</body>', '<script>window.OPENWAIVER_PREVIEW='+payload+';</script>\n<script>'+ (static/'app.js').read_text() +'</script>\n<script>'+ (static/'plans.js').read_text() +'</script>\n</body>')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding='utf-8')
        print(json.dumps({'preview':str(output), 'bytes':output.stat().st_size, 'synthetic_only':True}))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('OpenWaiver-preview.html'))
    make(p.parse_args().output)
