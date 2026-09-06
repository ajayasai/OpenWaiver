#!/usr/bin/env python3
"""Live physical workspace checks with synthetic retained evidence only."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'tests'))
from test_physical import fixture
from openwaiver.models import Principal
from openwaiver.service import Service
from openwaiver.store import Store


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('validation-results/physical-browser'))
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    from playwright.sync_api import sync_playwright,expect
    errors=[]
    with tempfile.TemporaryDirectory(prefix='openwaiver-physical-browser-') as directory:
        root=Path(directory);db=root/'workspace.sqlite3';auth=root/'auth.json'
        service=Service(Store(db));_,m,content=fixture()
        actor=Principal(name='synthetic-observer',role='contributor',projects=[m.scope.project])
        def ingest(manifest):
            return service.import_run(actor,content=content,format='json',scope=manifest.scope,
                revision=manifest.revision,complete=True,checked_categories=['drc'],
                physical_manifest=manifest.model_dump(mode='json'))
        before=ingest(m)
        changed=m.model_copy(deep=True);changed.revision='B'
        changed.targets['marker'].shapes[0].holes=[]
        after=ingest(changed)
        token=secrets.token_urlsafe(32)
        auth.write_text(json.dumps({'tokens':[{'name':'synthetic-observer','role':'viewer',
            'projects':[m.scope.project],'sha256':hashlib.sha256(token.encode()).hexdigest()}]}))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        env={**os.environ,'OPENWAIVER_DB':str(db),'OPENWAIVER_AUTH_FILE':str(auth),
             'PYTHONPATH':str(ROOT/'src')+os.pathsep+os.environ.get('PYTHONPATH','')}
        env.pop('OPENWAIVER_FEDERATION_FILE',None)
        with (root/'server.log').open('w') as log:
            server=subprocess.Popen([sys.executable,'-m','uvicorn','openwaiver.api:create_app','--factory',
                '--host','127.0.0.1','--port',str(port)],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                address=f'http://127.0.0.1:{port}'
                for _ in range(100):
                    try:
                        with urlopen(address+'/health',timeout=1) as response:
                            if response.status==200:break
                    except OSError:time.sleep(.1)
                else:raise RuntimeError('server failed: '+(root/'server.log').read_text())
                with sync_playwright() as pw:
                    browser=pw.chromium.launch(headless=True,args=['--no-sandbox'])
                    context=browser.new_context(viewport={'width':1440,'height':1100})
                    page=context.new_page();page.on('pageerror',lambda e:errors.append(str(e)))
                    page.goto(address+'/physical')
                    page.locator('#token').fill(token);page.locator('#login button').first.click()
                    expect(page.locator('#identity')).to_contain_text('synthetic-observer')
                    expect(page.locator('#token')).to_have_value('')
                    for prefix,run in [('before',before),('after',after)]:
                        page.locator('#'+prefix+'-run').fill(run.id)
                        page.locator('#'+prefix+'-id').fill('marker')
                    page.locator('#inspect button').first.click()
                    expect(page.locator('#before-drawing svg')).to_be_visible()
                    expect(page.locator('#before-info')).to_contain_text('"holes": 1')
                    expect(page.locator('#after-info')).to_contain_text('"holes": 0')
                    expect(page.locator('#status')).to_contain_text('Physical context differs')
                    assert page.locator('#before-drawing path.shape').first.get_attribute('fill-rule')=='evenodd'
                    layer=page.locator('#before-drawing .layer-toggle').first;layer.click()
                    expect(layer).to_have_attribute('aria-pressed','false');layer.click()
                    page.locator('#compare').click()
                    expect(page.locator('#comparison')).to_contain_text('"approvals_granted": 0')
                    expect(page.locator('#comparison')).to_contain_text('context_changed')
                    assert page.evaluate('Object.keys(localStorage).length+Object.keys(sessionStorage).length')==0
                    page.screenshot(path=str(args.output/'physical-desktop.png'),full_page=True)
                    page.set_viewport_size({'width':390,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    page.screenshot(path=str(args.output/'physical-mobile.png'),full_page=True)
                    page.locator('#logout').click()
                    expect(page.locator('#before-drawing svg')).to_have_count(0)
                    expect(page.locator('#comparison')).to_have_text('No comparison requested.')
                    browser.close()
                assert not errors,errors
            finally:
                server.terminate()
                try:server.wait(timeout=5)
                except subprocess.TimeoutExpired:server.kill();server.wait()
    result={'passed':True,'synthetic_only':True,'checks':['project-authorized retained physical evidence',
        'before/after hole-preserving SVG and provenance','layer controls and context-change comparison',
        '390px responsive layout','no persistent browser credentials','disconnect clears evidence'],
        'errors':errors}
    (args.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
