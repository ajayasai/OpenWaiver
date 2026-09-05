from datetime import timedelta
import pytest
from openwaiver.models import utcnow, Scope
from openwaiver.release import ReleaseManifest, gate_release


def manifest(run=None, **overrides):
    check = {"stream": "nightly", "tool": "verilator", "categories": ["lint"]}
    if run:
        check["run_id"] = run.id
    return ReleaseManifest.model_validate({"project": "chip", "revision": "rev-a", "checks": [check], **overrides})


def test_missing_stream_cannot_pass(service):
    result = gate_release(service.store, manifest())
    assert not result['gate_pass']
    assert 'missing' in str(result['blockers'])


def test_clean_required_stream(service, make_run):
    run = make_run([])
    assert gate_release(service.store, manifest(run))['gate_pass']


def test_multiple_runs_require_pin(service, make_run):
    make_run([])
    second = make_run([])
    assert not gate_release(service.store, manifest())['gate_pass']
    assert gate_release(service.store, manifest(second))['gate_pass']


@pytest.mark.parametrize('scope', [Scope(project='other', stream='nightly', tool='verilator'), Scope(project='chip', stream='other', tool='verilator'), Scope(project='chip', stream='nightly', tool='other')])
def test_scope_cannot_substitute(service, make_run, scope):
    run = make_run([], scope=scope)
    assert not gate_release(service.store, manifest(run))['gate_pass']


def test_wrong_revision(service, make_run):
    run = make_run([], revision='old')
    assert not gate_release(service.store, manifest(run))['gate_pass']


def test_partial_run(service, make_run):
    run = make_run([], complete=False)
    assert not gate_release(service.store, manifest(run))['gate_pass']


def test_missing_category(service, make_run):
    run = make_run([], checked_categories=['drc'])
    assert not gate_release(service.store, manifest(run))['gate_pass']


def test_age(service, make_run):
    run = make_run([])
    assert not gate_release(service.store, manifest(run), now=utcnow()+timedelta(days=2))['gate_pass']
    assert not gate_release(service.store, manifest(run), now=run.created_at-timedelta(seconds=1))['gate_pass']


def test_required_version(service, make_run):
    run = make_run([], tool_version='5.0')
    m = manifest(run)
    m.checks[0].tool_version = '5.1'
    assert not gate_release(service.store, m)['gate_pass']
    m.checks[0].tool_version = '5.0'
    assert gate_release(service.store, m)['gate_pass']


def test_waiver_must_still_be_effective(service, make_run, make_waiver):
    run = make_run()
    assert not gate_release(service.store, manifest(run))['gate_pass']
    make_waiver(run)
    assert gate_release(service.store, manifest(run))['gate_pass']


def test_second_required_stream_blocks(service, make_run):
    run = make_run([])
    m = manifest(run, checks=[{'stream': 'nightly', 'tool': 'verilator', 'categories': ['lint']}, {'stream':'physical', 'tool':'klayout', 'categories':['drc']}])
    assert not gate_release(service.store, m)['gate_pass']
    make_run([], scope=Scope(project='chip', stream='physical', tool='klayout'), checked_categories=['drc'])
    assert gate_release(service.store, m)['gate_pass']


@pytest.mark.parametrize('patch', [{'checks':[]}, {'project':' '}, {'max_age_hours':0}, {'max_age_hours':float('nan')}])
def test_manifest_validation(patch):
    with pytest.raises(ValueError):
        manifest(**patch)


def test_ambiguous_duplicate_check():
    with pytest.raises(ValueError):
        manifest(checks=[{'stream':'a','tool':'b','categories':['lint']}] * 2)


def test_naive_timestamp_refused(service):
    with pytest.raises(ValueError):
        gate_release(service.store, manifest(), now=utcnow().replace(tzinfo=None))
