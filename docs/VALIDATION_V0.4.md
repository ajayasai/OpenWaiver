# OpenWaiver 0.4 executed validation

## Verified source and hosted results

Source/test/workflow commit: `a80fd5ab47f0e27c57c51593665dabdd8cd612e5`.
[GitHub Actions run 34083762928](https://github.com/ajayasai/OpenWaiver/actions/runs/34083762928)
completed all five jobs successfully on 2026-09-07. This validation record was
added afterward without changing application, test or workflow source. The final
publication checks are shown in [pull request 4](https://github.com/ajayasai/OpenWaiver/pull/4).

| Executed check | Result |
|---|---|
| Full regression suite, inspected Python 3.13 report | **479 passed; zero failures, errors or skips** |
| New release-assurance regression cases | **71 executed**; total suite increased from 408 to 479 |
| Line coverage | **92.7773%**, 3,404 of 3,669 statements; no excluded statements |
| Python 3.11, 3.12, 3.13 CI jobs | All successful, including 90% coverage and explicit no-skip gates |
| Existing native KLayout cases | **23 executed**, none skipped |
| Inspected Python environment | Python 3.13.15; KLayout 0.30.12; PyJWT 2.13.0; cryptography 50.0.1 |
| Package build and isolated installed wheel | Passed, including release/physical module imports, assets and CLI entry points |
| New 71 cases rerun locally against the downloaded hosted wheel | **71 passed** |
| Existing live, offline and physical Chromium workflows | Passed |
| New authenticated release Chromium workflow | Passed; zero page errors |
| Native Verilator importer/exporter round-trip | Passed, Verilator 5.020 (Debian 5.020-1) |
| Actual Verilator + KLayout signed-release rehearsal | Passed; two actual findings, one per tool, reviewed and replayed |

Counts are pytest cases, including parametrized cases, not claims about all
possible inputs. The XML, coverage JSON, native result and browser result were
read directly from downloaded artifacts after validating their SHA-256 digests.
Desktop/mobile screenshots were visually inspected. No private keys or tokens
appear in those screenshots; the data is synthetic.

## What the tests establish

The release cases cover independently approved contracts; signed producer claims;
execution/import freshness; exact run/design/tool/policy bindings; scope grants;
key validity/revocation; missing required checks; complete/unfiltered and exit
status assertions; total/category budgets; expiry horizons; invalid or contradictory
review histories; duplicate inventory; API project isolation; create-only CLI
output; archive path/member/size/symlink controls; signature/member tampering;
independent historical replay; and live reconciliation after a waiver is revoked.

The native rehearsal executes actual Verilator lint and actual KLayout GDS reading
and `Region.width_check(120)`. It collects execution times and output hashes,
imports findings, applies independent fixture reviews, signs producer receipts,
and seals/replays a two-tool capsule with separate publisher authority. Removing
one receipt blocks release. A historically passing capsule fails current frozen-
state constraints after its execution receipts age. The separate regression case
checks that a post-freeze waiver revocation is detected by live reconciliation;
offline verification correctly leaves `release_usable_now` null.

The new browser test exercises a real authenticated server and project-scoped
viewer, passing and blocked two-stream evaluations, invalidation on editing,
390px responsiveness, memory-only credentials, clearing on disconnect, and an
unchanged audit head after read-only evaluation. The first hosted run exposed a
**test harness** string-evaluation conflict with the strict Content Security
Policy. Waits were changed to auto-retrying locator assertions and function
expressions. No product security policy or test outcome was weakened; all suites
passed on the subsequent commit recorded above.

## Artifact identity and retention

Artifacts are retained for 14 days for this run. Source and tests remain in Git.

- [Python 3.13 reports and packages](https://github.com/ajayasai/OpenWaiver/actions/runs/34083762928/artifacts/10004519517): ZIP SHA-256 `6dd7c845f244ba3fe1c2bfa23aa83ea3857d4d328623f4844e683d086ba6a49f`.
- [Browser results and synthetic screenshots](https://github.com/ajayasai/OpenWaiver/actions/runs/34083762928/artifacts/10004525899): ZIP SHA-256 `0b35f47894cab1b19fad5c784edd96ed87aaf98b5a39a22a5885f802092be3cb`.
- [Native Verilator and two-tool release results](https://github.com/ajayasai/OpenWaiver/actions/runs/34083762928/artifacts/10004514908): ZIP SHA-256 `a4b36d00a71bb578b47d714e8cbc3a5cb6122be66f84fb7855f4a71664caf970`.

Source changes were committed directly through the GitHub connection and validated
by hosted CI. No temporary write-enabled integration workflow was created for this
release. Ordinary CI uses pinned actions, read-only repository permissions and
non-persisted checkout credentials.

## Reproduction

```bash
python -m pip install -e '.[dev,browser,physical]'
python -m pytest --cov=openwaiver --cov-fail-under=90
playwright install chromium
python scripts/browser_smoke.py
python scripts/offline_smoke.py
python scripts/physical_browser_smoke.py
python scripts/release_browser_smoke.py
python scripts/native_verilator.py           # native Verilator required
python scripts/native_release_rehearsal.py   # native Verilator and KLayout required
python -m build
```

## Local development versus hosted validation

Local prepublication Python 3.13.5: 456 passed, 90.30% coverage, with the optional
KLayout test module skipped because its library was unavailable. Local browser
navigation was administratively blocked. Those local limits are not reported as
successful native/browser execution; the completed hosted checks above establish
the integrated results. The 71 new tests were additionally run against the actual
downloaded hosted wheel, using the local dependencies, and passed.

## Boundaries

Synthetic RTL/GDS only; no licensed proprietary product or production design was
used. Producer signatures authenticate supplied pipeline claims, not physical
execution or engineering correctness. Publisher signatures attest the captured
inventory, not independent completeness of the whole database history. Offline
replay cannot discover subsequent database changes. No end-to-end performance
claim, commercial superiority, externally immutable storage, deployed enterprise
IdP certification or chip-signoff qualification follows from these tests. See
[V0.4.md](V0.4.md) and [the comparison protocol](RELEASE_COMPARISON.md).
