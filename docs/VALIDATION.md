# Validation — OpenWaiver 0.1.0

## GitHub publication validation — 2026-09-05

The first public-repository validation completed successfully against commit `1f25f43c6d47f74b1afd8c8763e1eb9d2a83f10b` in [GitHub Actions run 33960334398](https://github.com/ajayasai/OpenWaiver/actions/runs/33960334398).

| Check | Observed result |
|---|---|
| Python 3.11, 3.12 and 3.13 | All three jobs passed the regression suite, Python compilation, JavaScript syntax check and package build |
| Live authenticated Chromium | Passed `scripts/browser_smoke.py`, including proposal, evidence upload, submission, separate reviewer approval and recalculated effective state |
| Browser safeguards | Token-free local/session storage and 390px responsive layout checks passed |

The CI run used synthetic data on GitHub-hosted Ubuntu runners. This closes the local environment's live-browser and Python-version validation gaps described below; it does not qualify proprietary adapters or production signoff. Later publication changes add documentation and regenerated synthetic screenshots without changing application behavior. Consult the repository's latest Actions run for the final commit's status.

## Original local validation

Recorded on 2026-09-05T08:02:21.317126+00:00. Inputs were synthetic. No commercial EDA licenses or proprietary design data were used.

### Automated checks actually executed locally

| Check | Observed result |
|---|---|
| Python regression/integration tests | **193 passed**, 0 failures, 0 errors, 0 skipped |
| Statement/line coverage | **88.51%** (1579/1784 executable lines) |
| Python compilation | `python -m compileall -q src tests scripts` passed |
| Built wheel | Installed into a temporary directory with existing runtime dependencies; package imports/static assets/CLI verified and all 193 tests passed again |
| JavaScript syntax | `node --check src/openwaiver/static/app.js` passed |
| Authenticated API lifecycle | Proposal → evidence → submission → independent approval → assessment → snapshot → amend/rebind/revoke tested through FastAPI TestClient |
| Offline Chromium UI | Six interaction groups passed; zero JavaScript errors; 390px mobile layout had no page-level horizontal overflow |
| Live HTTP browser workflow | **Not completed locally**: sandbox-managed Chromium blocked navigation to loopback (`ERR_BLOCKED_BY_ADMINISTRATOR`); subsequently passed on GitHub Actions above |
| Native format qualification | Synthetic documented fixtures passed; native EDA executable round trips not performed |

The server itself started and its loopback health endpoint returned HTTP 200 during the attempted local live-browser test. Offline checks exercised the same dashboard rendering, search, status/category filters, geometry overlay, waiver/history views, frozen comparisons and read-only policy, using data computed by the real backend. They **did not exercise authenticated browser writes**; those were separately covered at the API level and then in the successful GitHub Chromium run.

Coverage is measured on the Python package, not the JavaScript UI, and does not prove correctness or security. CLI coverage is lower than core engine/API coverage; inspect the recorded reports rather than assuming every path was exercised.

### Synthetic assessment performance

| Findings | Waivers | Median engine time | Repeats |
|---:|---:|---:|---:|
| 1,000 | 1,000 | 0.0333 s | 3 |
| 10,000 | 10,000 | 0.4618 s | 3 |

The 10,000-case workload produced exactly 6,000 effective waivers, 2,000 changed-target review candidates, 1,000 stale-context findings and 1,000 open findings. The removed counterparts were classified unused only because coverage was explicitly complete. No changed/stale/open case was automatically suppressed in these constructed cases.

These timings cover the **pure assessment function only**. Parsing, dataset construction, SQLite I/O, full audit traversal, UI, network and EDA execution are excluded. Unique hierarchy/object IDs make this an explicit controlled workload, not a worst-case candidate-density test or a claim of production capacity. There is no comparative performance evidence against commercial products.

## Reproduce

```bash
python -m pytest --cov=openwaiver --cov-report=term-missing
python scripts/offline_smoke.py
python scripts/browser_smoke.py  # requires browser navigation to a local HTTP server
python scripts/benchmark.py --sizes 1000 10000 --repeats 3 --output benchmark.json
```

Original local raw records: [summary and source hashes](validation/summary.json), [benchmark](validation/benchmark.json), [offline browser results](validation/offline-browser.json), [environment](validation/environment.json), [packaging smoke-test record](validation/packaging.json). The source hashes identify exactly which code and tests were present for the original local report. The downloadable source archive also retains its original local test XML. Repository publication regenerates `validation/tests.xml` on GitHub so its timing and environment belong to that run, not to the original local measurement.

## Remaining qualification

Docker, commercial head-to-head comparisons, proprietary adapter compatibility, native Verilator/KLayout execution, externally anchored audit infrastructure and independent penetration testing have not been performed. Do not translate passing synthetic tests into a foundry/signoff or “better than every closed-source alternative” claim.
