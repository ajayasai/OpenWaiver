#!/usr/bin/env python3
"""Sparse repeated-rule source movement: pure-engine timing, never a vendor comparison.

Run the SAME harness in separate processes with --source pointing to each checkout's
src directory. Input construction is excluded; Python version/host must be identical.
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import platform
import resource
import statistics
import sys
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'src')
    p.add_argument('--size', type=int, default=10000)
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if not 1 <= args.size <= 100000 or not 1 <= args.repeats <= 10:
        p.error('size must be 1..100000 and repeats 1..10')
    sys.path.insert(0, str(args.source.resolve()))
    from openwaiver import __version__
    from openwaiver.engine import assess, provenance
    from openwaiver.identity import approval_digest, fingerprint
    from openwaiver.models import Approval, Evidence, Policy, Run, Scope, Violation, Waiver, utcnow
    now = utcnow()
    scope = Scope(project='synthetic-repeated-rule', stream='lint', tool='synthetic')
    context = hashlib.sha256(b'declared synthetic context').hexdigest()
    old = [Violation(id=f'v{i}', category='lint', rule='WIDTH', severity='warning',
        message='Signal width differs from expected width', hierarchy='top', path='rtl/top.sv',
        line=300*i+1, context_hash=context) for i in range(args.size)]
    run = Run(id='synthetic-baseline', scope=scope, revision='A', complete=True, checked_categories=['lint'],
        source_sha256='a'*64, format='json', violations=old)
    evidence = Evidence(sha256='b'*64, filename='synthetic.txt', size=0, media_type='text/plain')
    waivers = []
    for i, v in enumerate(old):
        w = Waiver(id=f'w{i}', scope=scope, baseline_run_id=run.id, baseline_revision=run.revision,
            baseline_provenance=provenance(run), target=v, fingerprint=fingerprint(v),
            rationale='Synthetic benchmark only, not an engineering approval.', owner='owner', creator='owner',
            reviewers=['reviewer'], expires_on=now.date()+timedelta(days=30), status='approved', evidence=[evidence])
        w.approvals = [Approval(actor='reviewer', decision='approve', comment='Synthetic fixture', content_digest=approval_digest(w))]
        waivers.append(w)
    current = run.model_copy(update={'id': 'synthetic-current', 'revision': 'B',
        'violations': [v.model_copy(update={'line': v.line+1}) for v in old]})
    durations = []
    for _ in range(args.repeats):
        start = time.perf_counter()
        result = assess(current, waivers, Policy(), now.date())
        durations.append(time.perf_counter() - start)
        assert not result['gate_pass'] and not result['counts'].get('waived', 0)
    recoverable = sum(row['status'] == 'needs_review' and
        [candidate['waiver_id'] for candidate in row['candidates']] == [f'w{i}']
        for i, row in enumerate(result['violations']))
    payload = {'workload': 'same rule, hierarchy and source file; unique lines 300 apart; every finding moves +1',
        'synthetic_only': True, 'version': __version__, 'engine_sha256': hashlib.sha256((args.source / 'openwaiver/engine.py').read_bytes()).hexdigest(),
        'created_at': utcnow().isoformat(), 'findings': args.size, 'waivers': args.size, 'repeats': args.repeats,
        'seconds': durations, 'median_seconds': statistics.median(durations), 'counts': result['counts'],
        'correct_unique_review_candidates': recoverable, 'automatic_suppressions': result['counts'].get('waived', 0),
        'peak_process_rss_kib_linux': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'python': sys.version, 'platform': platform.platform(), 'candidate_limit': 256,
        'excludes': ['input generation', 'parsing', 'database and audit traversal', 'network', 'browser', 'EDA execution'],
        'limitations': ['Constructed sparse-source workload, not production capacity or commercial comparison.',
            'Dense source/geometry groups may still exceed the bounded candidate budget and remain ambiguous.',
            'Peak RSS includes data generation and output; it is not assessment-only incremental memory.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + '\n')
    print(json.dumps(payload, indent=2))


if __name__ == '__main__':
    main()
