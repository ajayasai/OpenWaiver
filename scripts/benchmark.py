#!/usr/bin/env python3
"""Reproducible SYNTHETIC pure-engine benchmark, not an EDA-tool comparison or DB throughput test."""
from __future__ import annotations
import argparse
from datetime import timedelta
import hashlib
import json
import platform
from pathlib import Path
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from openwaiver.engine import assess, provenance
from openwaiver.identity import approval_digest, fingerprint
from openwaiver.models import Approval, Evidence, Policy, Run, Scope, Violation, Waiver, utcnow


def dataset(n: int):
    now=utcnow()
    context=hashlib.sha256(b'synthetic-context-A').hexdigest()
    changed=hashlib.sha256(b'synthetic-context-B').hexdigest()
    scope=Scope(project='synthetic-benchmark',stream='all-lint',tool='synthetic')
    old=[Violation(id=f'v{i}',category='lint',rule='WIDTH',severity='warning',
        message='Signal width 32 differs from expected 16',hierarchy=f'top/u{i}',
        path=f'rtl/u{i}.sv',line=20,object_id=f'object-{i}',context_hash=context) for i in range(n)]
    baseline=Run(scope=scope,revision='A',complete=True,checked_categories=['lint'],
                 source_sha256=hashlib.sha256(b'synthetic').hexdigest(),format='json',violations=old)
    evidence=Evidence(sha256=hashlib.sha256(b'synthetic evidence').hexdigest(),filename='evidence.txt',size=18,media_type='text/plain')
    waivers=[]
    for v in old:
        w=Waiver(scope=scope,baseline_run_id=baseline.id,baseline_revision='A',baseline_provenance=provenance(baseline),
            target=v,fingerprint=fingerprint(v),rationale='Synthetic benchmark waiver; not engineering signoff.',owner='owner',
            creator='owner',reviewers=['reviewer'],expires_on=now.date()+timedelta(days=30),evidence=[evidence],status='approved')
        w.approvals=[Approval(actor='reviewer',decision='approve',comment='Synthetic review',content_digest=approval_digest(w))]
        waivers.append(w)
    current=[]
    for i,v in enumerate(old):
        value=v.model_copy(deep=True)
        if i >= n*9//10:
            value.hierarchy=f'top/new{i}'
            value.path=f'rtl/new{i}.sv'
            value.object_id=f'new-object-{i}'
        elif i >= n*8//10:
            value.context_hash=changed
        elif i >= n*6//10:
            value.line=21
        current.append(value)
    run=Run(scope=scope,revision='B',complete=True,checked_categories=['lint'],
            source_sha256=hashlib.sha256(b'synthetic B').hexdigest(),format='json',violations=current)
    expected={'waived':n*6//10, 'needs_review':n*8//10-n*6//10,
              'stale':n*9//10-n*8//10,'open':n-n*9//10}
    return run,waivers,expected


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sizes',nargs='+',type=int,default=[1000,10000])
    p.add_argument('--repeats',type=int,default=3)
    p.add_argument('--output',type=Path,default=Path('benchmark.json'))
    args=p.parse_args()
    if args.repeats<1 or any(n<10 or n>100000 for n in args.sizes):
        p.error('sizes must be 10–100000 and repeats positive')
    results=[]
    for n in args.sizes:
        run,waivers,expected=dataset(n)
        durations=[]
        for _ in range(args.repeats):
            start=time.perf_counter()
            result=assess(run,waivers,Policy(),utcnow().date())
            durations.append(time.perf_counter()-start)
            assert result['counts']==expected,(result['counts'],expected)
            assert len([w for w in result['waivers'] if w['status']=='unused'])==n-n*9//10
            assert not result['gate_pass']
        item={'findings':n,'waivers':n,'repeats':args.repeats,'seconds':durations,
              'median_seconds':statistics.median(durations),'counts':result['counts'],
              'false_automatic_suppressions_in_constructed_cases':0,
              'checks_passed':True}
        results.append(item)
        print(json.dumps(item),flush=True)
    output={'benchmark':'synthetic-pure-assessment-engine', 'created_at':utcnow().isoformat(),
            'python':sys.version,'platform':platform.platform(),'processor':platform.processor(),
            'limitations':['Excludes parsing, database access, full audit traversal, browser and network.',
                          'Not production capacity, commercial comparison, or a statistical safety guarantee.',
                          'Workload uses unique hierarchy/object IDs and controlled source/context changes.'],
            'results':results}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(output,indent=2)+'\n')


if __name__=='__main__':
    main()
