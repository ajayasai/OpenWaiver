#!/usr/bin/env python3
"""Test the synthetic offline dashboard in Chromium. No HTTP/browser navigation is required.

This checks rendered interactions, not authenticated writes to the live API.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from make_preview import make


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=Path('browser-results/offline'))
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    from playwright.sync_api import sync_playwright, expect
    checks=[];errors=[]
    with tempfile.TemporaryDirectory(prefix='openwaiver-offline-') as temp:
        preview=Path(temp)/'preview.html';make(preview)
        with sync_playwright() as pw:
            executable=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE',pw.chromium.executable_path)
            if not Path(executable).exists():
                executable=shutil.which('chromium') or shutil.which('chromium-browser') or executable
            browser=pw.chromium.launch(headless=True,executable_path=executable,args=['--no-sandbox'])
            page=browser.new_page(viewport={'width':1440,'height':1080},device_scale_factor=1)
            page.on('pageerror',lambda e: errors.append(str(e)))
            page.on('console',lambda m:errors.append(m.text) if m.type=='error' else None)
            page.set_content(preview.read_text(),wait_until='load')
            expect(page.locator('.metric-value')).to_have_text(['10','2','3','1'])
            expect(page.locator('#preview-banner')).to_be_visible()
            expect(page.locator('#import-open')).to_be_disabled()
            page.screenshot(path=str(args.output/'overview.png'),full_page=True)
            checks.append('synthetic overview uses actual calculated 10/2/3/1 metrics')
            page.locator('[data-view="violations"]').click()
            page.locator('#search').fill('M2.SPACING')
            expect(page.locator('#findings-body tr')).to_have_count(1)
            page.locator('#findings-body [data-finding]').click()
            expect(page.locator('#drawer .geometry')).to_be_visible()
            expect(page.locator('[data-rebind]')).to_be_disabled()
            page.screenshot(path=str(args.output/'geometry-review.png'),full_page=True)
            page.locator('[data-close-drawer]').click()
            page.locator('#search').fill('')
            expect(page.locator('#findings-body tr')).to_have_count(10)
            page.locator('#status-filter').select_option('stale')
            expect(page.locator('#findings-body tr')).to_have_count(1)
            page.locator('#status-filter').select_option('')
            page.locator('#category-filter').select_option('drc')
            expect(page.locator('#findings-body tr')).to_have_count(3)
            page.locator('#category-filter').select_option('')
            checks.append('search, status/category filters and before/after geometry')
            page.locator('[data-view="waivers"]').click()
            expect(page.locator('#waivers-view tbody tr')).to_have_count(8)
            page.locator('#waivers-view [data-waiver]').first.click()
            expect(page.locator('#record-history')).not_to_contain_text('Loading')
            expect(page.locator('#record-history .evidence-row').first).to_be_visible()
            page.locator('[data-close-drawer]').click()
            checks.append('waiver register, evidence metadata and historical events')
            page.locator('[data-view="compare"]').click()
            expect(page.locator('#compare-result')).to_contain_text('Effective-state count changes')
            expect(page.locator('#freeze-open')).to_be_disabled()
            page.screenshot(path=str(args.output/'candidate-comparison.png'),full_page=True)
            checks.append('frozen candidate comparison from actual backend snapshots')
            page.locator('[data-view="audit"]').click()
            expect(page.locator('.audit-banner')).to_contain_text('verified')
            page.locator('[data-view="policy"]').click()
            expect(page.locator('#policy-json')).to_have_attribute('readonly','')
            expect(page.locator('#save-policy')).to_be_disabled()
            checks.append('verified synthetic audit history and read-only policy')
            page.locator('[data-view="overview"]').click()
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(args.output/'mobile.png'),full_page=True)
            overflow=page.evaluate('document.documentElement.scrollWidth > innerWidth + 2')
            if overflow:
                details=page.evaluate('Array.from(document.querySelectorAll("body *")).filter(e=>e.getBoundingClientRect().right>innerWidth+2).slice(0,20).map(e=>({tag:e.tagName,cls:e.className,right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width}))')
                raise AssertionError('mobile horizontal overflow: '+json.dumps(details))
            checks.append('390px responsive layout without page-level horizontal overflow')
            browser.close()
    result={'mode':'offline synthetic UI only; live browser writes not exercised', 'browser':'Chromium',
            'passed':not errors,'checks':checks,'errors':errors}
    (args.output/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    assert not errors,errors


if __name__=='__main__':
    main()
