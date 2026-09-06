# Changelog

## 0.3.0 — 2026-09-06

Retained, report-bound physical context; native GDS/OASIS extraction through KLayout; orthogonal whole-neighborhood comparisons; read-only before/after geometry workspace; explicit physical CLI; pinned-key federated JWT access-token validation and project mapping. Changed context blocks approval reuse. Existing record serialization is preserved when physical evidence is absent. Qualification remains version/fixture-specific.

## 0.2.0 — 2026-09-05

Added bounded indexed candidate retrieval; exact project token grants with expiry, revocation and hot reload; atomic, preview-bound proposal/amendment plans in YAML/browser/API/CLI; content-derived explicit dependency manifests; offline Ed25519 artifact signatures and append-aware ledger checkpoints; standalone semantic bundle replay; and a native Verilator round-trip harness. Native export now refuses collateral suppression of unapproved findings sharing the generated rule/file/line scope. CI adds a 90% line-coverage gate, native executable checks, retained validation artifacts and pinned action revisions.

283 local tests passed. Repeated-rule synthetic 10k assessment: 9.138 s to 0.355 s median vs v0.1, with all intended candidates recovered and no changed findings automatically waived. 100k: 4.409 s median. No commercial performance or signoff qualification claim. See `docs/V0.2.md`.

Compatibility: persisted model/fingerprint schemas unchanged; legacy tokens remain workspace-wide; new `auth-create` requires explicit project or workspace grants. SSO, KMS/WORM, proprietary adapter qualification and full physical topology remain outside this release.

## 0.1.0 — 2026-09-05

Initial implementation: strict cross-tool ingestion; semantic fingerprints; conservative moved/reshaped/context-change detection; independent review lifecycle; content-addressed evidence; SQLite transactional audit/history; role-authenticated API and browser; CLI/CI gates; explicit multi-tool release manifests; deterministic YAML projections and evidence bundles; immutable candidate comparisons; SARIF/JUnit/HTML exports; opt-in lossy Verilator control exporter; synthetic demo, regression tests, browser smoke test and reproducible engine benchmark.

Not certified for tapeout. Proprietary vendor adapters, SSO, multi-tenant isolation, immutable external audit and full physical topology support are not included.
