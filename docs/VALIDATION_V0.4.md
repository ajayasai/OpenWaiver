# OpenWaiver 0.4 executed validation

The new release-assurance tests exercise approved contracts, signed producer claims,
execution/import freshness, explicit provenance, risk budgets, project isolation,
invalid review histories, ZIP and signature tampering, semantic replay, and live
reconciliation after revocation. They also run the CLI and real authenticated API.

## Local execution before publication

Python 3.13.5: **456 passed**; native KLayout module skipped because the optional
library is not installed locally. This is **not** an all-native passing-suite claim.
Line coverage: **90.30%** with the 90% gate passed. The source contains **71 new
pytest cases** relative to 0.3. Package wheel build and Python/JavaScript compilation
passed. New-module local coverage exceeds 94% for execution receipts, release
contracts, capsules, CLI and API routes.

The local browser could not navigate to the test server due to its administrative
navigation policy (`ERR_BLOCKED_BY_ADMINISTRATOR`). No local live-browser success is
claimed. Final native and browser results must be read from the PR's hosted CI.

## Hosted checks configured

Python 3.11/3.12/3.13 with the physical extra, full regression suite, a 90% coverage
floor and explicit no-skip validation; package build/isolated installed-wheel
assets and entry points; existing live/offline/physical Chromium tests; new release
workspace Chromium tests; existing native Verilator round-trip; and a new actual
Verilator plus KLayout two-tool signed-release rehearsal.

Native rehearsal uses only synthetic RTL/GDS. No licensed proprietary product or
production design is used. Tests and source are reproducible; see `V0.4.md` for
commands, trust boundaries and the distinction between frozen and live validity.

Detailed final hosted results are recorded in the publication PR before merge.
No end-to-end performance claim, commercial superiority, immutable-storage guarantee,
external IdP deployment or chip-signoff qualification follows from these tests.
