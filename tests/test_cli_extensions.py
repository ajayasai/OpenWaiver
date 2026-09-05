import json

import pytest
import yaml

from openwaiver.cli import main
from openwaiver.interchange import bundle


def test_cli_plan_round_trip(service, make_run, tmp_path, capsys):
    run = make_run()
    prefix = ['--db', str(service.store.path), '--actor', 'alice']
    plan, preview, result = [tmp_path / n for n in ('plan.yaml', 'preview.json', 'result.json')]
    assert main(prefix + ['plan-template', run.id, '--violation', 'v1', '--reviewers', 'bob',
        '--rationale', 'Explicitly reviewed engineering exception for this source revision.',
        '--valid-revision', run.revision, '--output', str(plan)]) == 0
    assert main(prefix + ['plan-preview', str(plan), '--output', str(preview)]) == 0
    digest = json.loads(preview.read_text())['preview_digest']
    assert main(prefix + ['plan-apply', str(plan), '--expected-digest', digest, '--output', str(result)]) == 0
    assert json.loads(result.read_text())['results'][0]['status'] == 'proposed'
    assert main(prefix + ['plan-apply', str(plan), '--expected-digest', digest]) == 2
    assert 'changed since' in capsys.readouterr().err


def test_cli_context_build_and_compare(tmp_path, capsys):
    (tmp_path / 'top.sv').write_text('module top; endmodule\n')
    specification = {'scope': {'project': 'p', 'tool': 't', 'stream': 's'}, 'revision': 'A',
        'nodes': {'top.sv': {}}, 'targets': {'v': ['top.sv']}}
    spec = tmp_path / 'spec.yaml'
    spec.write_text(yaml.safe_dump(specification))
    before, after, result = [tmp_path / n for n in ('a.json', 'b.json', 'diff.json')]
    args = ['context-build', str(spec), '--root', str(tmp_path), '--output']
    assert main(args + [str(before)]) == 0
    (tmp_path / 'top.sv').write_text('module top; wire change; endmodule\n')
    assert main(args + [str(after)]) == 0
    assert main(['context-compare', str(before), str(after), '--output', str(result)]) == 0
    assert json.loads(result.read_text())['targets_impacted'] == ['v']
    assert main(args + [str(before)]) == 2  # Never silently overwrite evidence.


def test_cli_offline_signature_checkpoint_and_semantic_bundle(service, actors, make_run, make_waiver, tmp_path, capsys):
    run = make_run()
    make_waiver(run)
    snap = service.freeze(actors['bob'], run.id, 'candidate', require_clean=True)
    data = bundle(service, snap.id)
    archive = tmp_path / 'bundle.zip'
    archive.write_bytes(data)
    private, public, signature, checkpoint = [tmp_path / n for n in ('signing.key', 'trusted.pub', 'signature.json', 'checkpoint.json')]
    assert main(['keygen', '--private-key', str(private), '--public-key', str(public)]) == 0
    assert main(['sign-file', str(archive), '--private-key', str(private), '--subject', 'project/candidate', '--output', str(signature)]) == 0
    verify = ['verify-evidence', str(archive), '--signature', str(signature), '--public-key', str(public), '--subject', 'project/candidate']
    capsys.readouterr()
    assert main(verify) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['assessment_replayed'] and result['signature_verified'] and result['externally_anchored']
    assert main(['verify-file', str(archive), '--signature', str(signature), '--public-key', str(public), '--subject', 'other']) == 2
    prefix = ['--db', str(service.store.path)]
    assert main(prefix + ['checkpoint', '--private-key', str(private), '--subject', 'project/ledger', '--output', str(checkpoint)]) == 0
    assert main(prefix + ['verify-checkpoint', '--signature', str(checkpoint), '--public-key', str(public), '--subject', 'project/ledger']) == 0
    assert main(['verify-evidence', str(archive), '--signature', str(signature)]) == 2
    archive.write_bytes(data + b'changed bytes')
    assert main(['verify-file', str(archive), '--signature', str(signature), '--public-key', str(public), '--subject', 'project/candidate']) == 2


@pytest.mark.parametrize('nodes', [None, [], 'bad', {'top.sv': []}])
def test_cli_context_rejects_malformed_nodes_without_traceback(nodes, tmp_path, capsys):
    spec = tmp_path / 'bad.yaml'
    spec.write_text(yaml.safe_dump({'nodes': nodes}))
    assert main(['context-build', str(spec), '--root', str(tmp_path), '--output', str(tmp_path / 'out')]) == 2
    assert 'openwaiver:' in capsys.readouterr().err


def test_cli_auth_grants_expiry_and_explicit_workspace(tmp_path):
    path = tmp_path / 'auth.json'
    args = ['auth-create', '--file', str(path), '--name', 'alice', '--auth-role', 'contributor']
    assert main(args + ['--project', 'chip', '--expires-at', '2099-01-01T00:00:00+00:00']) == 0
    assert main(args + ['--all-projects']) == 0
    records = json.loads(path.read_text())['tokens']
    assert records[0]['projects'] == ['chip'] and records[0]['expires_at']
    assert records[1]['projects'] is None
    assert main(args + ['--project', 'chip', '--expires-at', '2099-01-01T00:00:00']) == 2
