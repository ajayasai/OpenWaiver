# OpenWaiver v0.3 executed validation

## Verified source and run

Application/test source commit: `3c6a41787e1d17977c20a4c19238bcd94cdee866`.
[GitHub Actions run 34022290716](https://github.com/ajayasai/OpenWaiver/actions/runs/34022290716)
completed successfully on 2026-09-06. This report and the security-guide update
were added afterward without changing application/test source. The subsequent
PR-head CI is shown in [pull request 3](https://github.com/ajayasai/OpenWaiver/pull/3).

| Executed check | Result |
|---|---|
| Full regression suite, Python 3.13 artifact | 408 tests; 0 failures, 0 errors, 0 skipped |
| Line coverage | 2,869 of 3,115 statements; 92.1027% |
| Native KLayout cases | 23 executed; none skipped |
| Python 3.11, 3.12, 3.13 CI jobs | All successful, each with the 90% coverage gate and no-skip check |
| Native environment in Python 3.13 job | Python 3.13.15, KLayout 0.30.12, PyJWT 2.13.0 |
| Package build and isolated installed-wheel check | Passed; physical assets, module imports and `openwaiver-physical` entry point verified |
| Existing live Chromium and offline browser workflows | Passed |
| New authenticated physical browser workflow | Passed; no page errors |
| Existing actual Verilator integration | Passed in a separate native-executable job |

The suite increased from 283 to 408 tests. Parametrized cases are counted by
pytest. One property test additionally checks 256 seeded polygon winding/start
variants; those variants are not added to the 408 test count.

## Reproduction

```bash
python -m pip install -e '.[dev,browser,physical]'
python -m pytest --cov=openwaiver --cov-fail-under=90
playwright install chromium
python scripts/browser_smoke.py
python scripts/offline_smoke.py
python scripts/physical_browser_smoke.py
python scripts/native_verilator.py  # requires the native Verilator executable
python -m build
```

The physical extra is required for native KLayout tests. The CI explicitly fails
if those tests are missing or skipped. Local isolated tests were useful during
development, but the full integrated native/backend/browser claims above come
from the hosted execution, not local mocks.

## What the native tests establish

Synthetic GDS/OASIS files are written and reread by KLayout. Native `Region.width_check`
produces real geometry results. Tests cover unique cell placement, regular
arrays, nested rotation/mirroring, explicit ambiguity rejection, exact units,
shape properties, unsupported input rejection and a complete waiver lifecycle.
An unchanged width marker becomes stale after a neighboring layer changes.
The earlier implementation error calling array iteration on `Instance` was
caught by native CI and corrected to `Instance.cell_inst.each_cplx_trans()`;
array/nested-placement/property tests were added and the full suite rerun.

The physical UI's real authenticated browser test checks retained shapes and
hole rendering, layer controls, changed-context comparison with zero approvals,
390-pixel layout, empty browser persistent credential storage, and evidence
clearing on disconnect. The generated desktop/mobile screenshots were also
visually inspected. They contain only synthetic geometry and cleared token fields.

## Retained CI artifacts and byte verification

Artifacts expire according to GitHub retention policy (14 days for this run).
The source tests and CI remain reproducible in the repository.

- [Python 3.13 tests, coverage, environment and packages](https://github.com/ajayasai/OpenWaiver/actions/runs/34022290716/artifacts/9985903446): ZIP SHA-256 `298ea3a2421ec903cad7fe0bcb506fd6f89cc0cf6dff7cc29475e13e4a8733ed`.
- [Browser results and synthetic screenshots](https://github.com/ajayasai/OpenWaiver/actions/runs/34022290716/artifacts/9985904952): ZIP SHA-256 `5550d942b6e2f0cc64c83d7a1678956fd57e4d8ee3a1cdec176c6134624f4b62`.
- [Native Verilator result](https://github.com/ajayasai/OpenWaiver/actions/runs/34022290716/artifacts/9985901912).

The Python and browser ZIPs were downloaded through the GitHub connection and
matched the service-reported SHA-256 digests before inspection. The XML report,
coverage JSON, environment JSON and physical browser result were read directly.
Earlier guarded integration also verified all 12 transferred source/test/UI
file digests before applying exact-version patches to the v0.2 core. Temporary
write-enabled integration tools were removed before the final PR checks.

## What has not been established

These are regression, interoperability and browser tests on synthetic inputs,
not independent security certification or a licensed commercial benchmark.
Native qualification applies only to the installed tool versions and exercised
geometry/transform subset. No full physical/electrical signoff, actual enterprise
IdP deployment, proprietary-adapter qualification, production scalability SLA or
universal superiority is claimed. See [the operating/trust guide](V0.3.md).
