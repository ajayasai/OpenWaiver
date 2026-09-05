#!/usr/bin/env python3
"""Exercise a real authenticated server in Chromium; only synthetic fixtures are generated."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from openwaiver.cli import write_auth
from openwaiver.demo import seed
from openwaiver.models import utcnow


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=Path('browser-results'))
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    from playwright.sync_api import sync_playwright, expect
    checks=[]
    errors=[]
    with tempfile.TemporaryDirectory(prefix='openwaiver-browser-') as temp:
        directory=Path(temp)
        db=directory/'demo.sqlite3'
        auth=directory/'auth.json'
        demo=seed(db)
        tokens={name:write_auth(auth,name,role) for name,role in [('engineer','contributor'),('reviewer','reviewer'),('observer','viewer')]}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port=sock.getsockname()[1]
        env={**os.environ,'PYTHONPATH':str(ROOT/'src')+os.pathsep+os.environ.get('PYTHONPATH','')}
        command=[sys.executable,'-m','openwaiver','--db',str(db),'serve','--auth-file',str(auth),'--port',str(port)]
        with (directory/'server.log').open('w') as log:
            server=subprocess.Popen(command,env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                address=f'http://127.0.0.1:{port}'
                for _ in range(100):
                    try:
                        with urlopen(address+'/health',timeout=1) as response:
                            if response.status==200:
                                break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('server did not start: '+(directory/'server.log').read_text())
                with sync_playwright() as pw:
                    options={'headless':True,'args':['--no-sandbox']}
                    executable=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE', pw.chromium.executable_path)
                    if not Path(executable).exists():
                        executable=shutil.which('chromium') or shutil.which('chromium-browser') or executable
                    if Path(executable).exists():
                        options['executable_path']=executable
                    browser=pw.chromium.launch(**options)
                    context=browser.new_context(viewport={'width':1440,'height':1080},device_scale_factor=1)
                    page=context.new_page()
                    page.on('pageerror',lambda e:errors.append(str(e)))
                    page.on('console',lambda m:errors.append(m.text) if m.type=='error' and 'favicon' not in m.text else None)
                    def login(name):
                        page.goto(address)
                        page.locator('#login-token').fill(tokens[name])
                        page.locator('#login-form button').click()
                        expect(page.locator('#login-dialog')).not_to_be_visible()
                        expect(page.locator('#nav-count')).to_have_text('10')
                    login('observer')
                    expect(page.locator('#overview-view')).to_contain_text('Review required before proceeding')
                    expect(page.locator('.metric-value')).to_have_text(['10','2','3','1'])
                    checks.append('authenticated live overview and real calculated counters')
                    page.screenshot(path=str(args.output/'overview.png'),full_page=True)
                    page.locator('[data-view="violations"]').click()
                    page.locator('#search').fill('M2.SPACING')
                    expect(page.locator('#findings-body tr')).to_have_count(1)
                    page.locator('#findings-body [data-finding]').click()
                    expect(page.locator('#drawer .geometry')).to_be_visible()
                    page.screenshot(path=str(args.output/'geometry-review.png'),full_page=True)
                    page.locator('[data-close-drawer]').click()
                    page.locator('#search').fill('')
                    expect(page.locator('#findings-body tr')).to_have_count(10)
                    page.locator('#status-filter').select_option('stale')
                    expect(page.locator('#findings-body tr')).to_have_count(1)
                    page.locator('#status-filter').select_option('')
                    checks.append('finding search, effective-state filter and geometry inspection')
                    page.locator('[data-view="waivers"]').click()
                    expect(page.locator('#waivers-view tbody tr')).to_have_count(8)
                    page.locator('#waivers-view [data-waiver]').first.click()
                    expect(page.locator('#record-history')).not_to_contain_text('Loading')
                    page.locator('[data-close-drawer]').click()
                    checks.append('waiver register and historical audit content')
                    page.locator('[data-view="compare"]').click()
                    expect(page.locator('#compare-result')).to_contain_text('Effective-state count changes')
                    page.screenshot(path=str(args.output/'candidate-comparison.png'),full_page=True)
                    checks.append('immutable snapshot comparison')
                    page.locator('[data-view="audit"]').click()
                    expect(page.locator('.audit-banner')).to_contain_text('verified')
                    page.locator('[data-view="policy"]').click()
                    expect(page.locator('#policy-json')).to_have_attribute('readonly','')
                    expect(page.locator('#save-policy')).to_be_disabled()
                    checks.append('audit verification and viewer read-only policy')
                    # Complete a browser-only proposal -> evidence -> submission -> independent approval.
                    login('engineer')
                    page.locator('[data-view="violations"]').click()
                    page.locator('#findings-body [data-finding="finding-11"]').click()
                    page.locator('[data-propose="finding-11"]').click()
                    page.locator('#modal textarea[name="rationale"]').fill('Synthetic browser test: engineering exception with bounded conditions.')
                    page.locator('#modal input[name="reviewers"]').fill('reviewer')
                    page.locator('#modal-form button[type="submit"]').click()
                    expect(page.locator('#modal')).not_to_be_visible()
                    page.locator('#drawer [data-action="attach"]').click()
                    page.locator('#modal input[type="file"]').set_input_files({'name':'browser-evidence.txt','mimeType':'text/plain','buffer':b'Synthetic browser approval evidence.'})
                    page.locator('#modal-form button[type="submit"]').click()
                    expect(page.locator('#modal')).not_to_be_visible()
                    page.locator('#drawer [data-action="submit"]').click()
                    expect(page.locator('#drawer .status-pill').first).to_have_text('submitted')
                    login('reviewer')
                    page.locator('[data-view="waivers"]').click()
                    page.locator('#waivers-view tr').filter(has_text='M1.WIDTH').locator('[data-waiver]').click()
                    page.locator('#drawer [data-action="approve"]').click()
                    page.locator('#modal textarea[name="comment"]').fill('Independent synthetic browser review accepted.')
                    page.locator('#modal-form button[type="submit"]').click()
                    expect(page.locator('#modal')).not_to_be_visible()
                    expect(page.locator('#drawer .status-pill').first).to_have_text('approved')
                    page.locator('[data-close-drawer]').click()
                    page.locator('[data-view="overview"]').click()
                    expect(page.locator('.metric-value').nth(1)).to_have_text('3')
                    checks.append('browser end-to-end propose, attach, submit, independent approve and effective recalculation')
                    # New review-plan UI: explicit selection, preview, atomic proposal (no approval).
                    login('engineer')
                    page.locator('[data-view="plans"]').click()
                    page.locator('#plan-ids').fill('finding-9')
                    page.locator('#plan-reviewers').fill('reviewer')
                    page.locator('#plan-rationale').fill('Synthetic reviewed plan for a bounded macro pin exception.')
                    page.locator('#generate-plan').click()
                    expect(page.locator('#plan-yaml')).to_have_value(__import__('re').compile('expected_audit_head'))
                    page.locator('#preview-plan').click()
                    expect(page.locator('#apply-plan')).to_be_enabled()
                    expect(page.locator('#plan-result')).to_contain_text('"approvals_granted": 0')
                    page.screenshot(path=str(args.output/'review-plan.png'), full_page=True)
                    page.locator('#apply-plan').click()
                    expect(page.locator('#plan-result')).to_contain_text('"applied": true')
                    expect(page.locator('#apply-plan')).to_be_disabled()
                    page.locator('[data-view="waivers"]').click()
                    expect(page.locator('#waivers-view tr').filter(has_text='LVS.PIN')).to_contain_text('proposed')
                    checks.append('review-plan browser template, preview, atomic apply and zero granted approvals')
                    # Confirm bearer storage isn't written into web storage.
                    assert page.evaluate('localStorage.length')==0
                    assert page.evaluate('sessionStorage.length')==0
                    checks.append('no persisted token in localStorage or sessionStorage')
                    page.set_viewport_size({'width':390,'height':844})
                    page.screenshot(path=str(args.output/'mobile.png'),full_page=True)
                    # Horizontal tables scroll inside their own containers, not the entire page.
                    overflow=page.evaluate('document.documentElement.scrollWidth > innerWidth + 2')
                    if overflow:
                        raise AssertionError('mobile document has unintended horizontal overflow')
                    checks.append('390px responsive layout without document horizontal overflow')
                    browser.close()
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill();server.wait()
    # Chromium may report a missing favicon; unrelated to UI safety. All actual JS/CSP errors fail.
    meaningful=[e for e in errors if '404 (Not Found)' not in e]
    result={'created_at':utcnow().isoformat(),'browser':'Chromium','checks':checks,'passed':not meaningful,'errors':meaningful,'synthetic_only':True}
    (args.output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if meaningful:
        raise AssertionError(meaningful)


if __name__=='__main__':
    main()
