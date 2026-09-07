#!/usr/bin/env python3
"""Exercise the authenticated release workspace. All data is synthetic."""
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
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from openwaiver.identity import canonical
from openwaiver.service import Service
from openwaiver.store import Store
from release_fixture import synthetic_workspace


def main():
    from playwright.sync_api import sync_playwright, expect
    p=argparse.ArgumentParser();p.add_argument("--output",default="validation-results/release-browser");args=p.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ow-release-browser-") as folder:
        folder=Path(folder)
        service=Service(Store(folder/"workspace.sqlite3"))
        contract,trust,receipts,_,_=synthetic_workspace(service)
        token=secrets.token_urlsafe(32)
        auth=[dict(name="release-reader",role="viewer",projects=["sample-chip"],sha256=hashlib.sha256(token.encode()).hexdigest())]
        (folder/"auth.json").write_text(canonical({"tokens":auth}))
        (folder/"trust.json").write_text(canonical(trust))
        with socket.socket() as sock: sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        env={**os.environ,"OPENWAIVER_DB":str(service.store.path),"OPENWAIVER_AUTH_FILE":str(folder/"auth.json"),
             "OPENWAIVER_RELEASE_TRUST_FILE":str(folder/"trust.json"),"PYTHONPATH":str(ROOT/"src")}
        server=subprocess.Popen([sys.executable,"-m","uvicorn","openwaiver.api:create_app","--factory","--host","127.0.0.1","--port",str(port)],
                                env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            url=f"http://127.0.0.1:{port}"
            for _ in range(100):
                try:
                    urllib.request.urlopen(url+"/health",timeout=1).close();break
                except OSError: time.sleep(.1)
            else: raise RuntimeError("test server failed to start")
            with service.store.transaction(write=False) as conn: before=service.store.head(conn)
            with sync_playwright() as pw:
                options={"headless":True}
                if os.environ.get("OPENWAIVER_CHROMIUM"): options["executable_path"]=os.environ["OPENWAIVER_CHROMIUM"]
                browser=pw.chromium.launch(**options)
                page=browser.new_page(viewport={"width":1440,"height":1100})
                errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
                page.goto(url+"/releases")
                page.fill("#token",token);page.click("#connect")
                expect(page.locator("#identity")).to_contain_text("release-reader")
                assert page.input_value("#token")==""
                page.fill("#contract",canonical(contract))
                page.fill("#receipts",canonical(receipts and [r.model_dump(mode="json") for r in receipts]))
                page.click("#evaluate");expect(page.locator("#verdict")).to_have_text("Contract satisfied")
                assert page.locator(".check").count()==2
                page.screenshot(path=str(out/"release-desktop.png"),full_page=True)
                page.fill("#receipts","[]")
                assert page.locator("#decision").is_hidden() and page.locator("#download").is_disabled()
                page.click("#evaluate");expect(page.locator("#verdict")).to_have_text("Release blocked")
                assert "missing" in page.locator("#blockers").inner_text()
                page.set_viewport_size({"width":390,"height":844})
                assert page.evaluate("() => document.documentElement.scrollWidth <= innerWidth")
                page.screenshot(path=str(out/"release-mobile.png"),full_page=True)
                assert page.evaluate("() => localStorage.length === 0 && sessionStorage.length === 0")
                page.click("#disconnect")
                assert page.locator("#decision").is_hidden() and page.input_value("#contract")==""
                assert page.input_value("#receipts")=="[]"
                assert page.locator("#result-json").inner_text()==""
                assert not errors,errors
                browser.close()
            with service.store.transaction(write=False) as conn: assert service.store.head(conn)==before
            result={"passed":True,"synthetic_only":True,"errors":errors,"checks":[
                "project-authorized two-stream release evaluation","signed execution receipts and pinned contract",
                "missing receipts block release","edits invalidate previous verdict","390px responsive layout",
                "memory-only credentials and disconnect clearing","read-only evaluation leaves audit head unchanged"]}
            (out/"result.json").write_text(json.dumps(result,indent=2))
            print(json.dumps(result,indent=2))
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill();server.wait()


if __name__=="__main__":main()
