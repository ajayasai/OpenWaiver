# Competitive evidence and qualification boundaries

Reviewed 2026-09-05. This is a claim/evidence ledger, not an unsupported winner ranking. A public feature page is not proof of performance, a missing public feature statement is not proof of absence, and these products do not all serve identical scopes.

## Primary-source comparison baseline

| Product / source | What its owner documents | Implication for OpenWaiver |
|---|---|---|
| Siemens [Calibre Auto-Waivers](https://www.siemens.com/en-gb/products/ic/calibre-design/physical-verification/auto-waivers/) | Integrated DRC waiver processing, retained waiver information and hierarchy-invariant handling | A generic geometry viewer is not equivalent to its native hierarchy-aware engine. OpenWaiver has not qualified Calibre execution or hierarchical physical matching. |
| Synopsys [IC Validator VUE waiver flow](https://www.synopsys.com/implementation-and-signoff/resources/videos/waiver-flow-one.html) | Create waivers, import them for subsequent runs, append new waivers; VUE/PYDB paths | Import/reuse is not unique to OpenWaiver. A proprietary adapter requires official schemas and real executable tests. |
| Cadence [Verisium Manager](https://www.cadence.com/en_US/home/tools/system-design-and-verification/ai-driven-verification/verisium-manager.html) | Enterprise verification management spanning verification engines and coverage | Do not call OpenWaiver's local SQLite dashboard an enterprise verification-platform replacement. |
| Verilator [control-file specification](https://verilator.org/guide/latest/control.html) | Native controls can select rule, source file and line, with other matching forms | The current OpenWaiver exporter deliberately implements only the documented rule/file/line subset. Preflight now rejects collateral unapproved same-line suppression; native round-trip checks still qualify only the executed version/fixture. |

## Claims implemented and falsifiable in 0.2

| Claim | Reproduction / test | Boundary |
|---|---|---|
| Faster sparse repeated-rule candidate assessment than OpenWaiver 0.1 | `scripts/benchmark_candidates.py`; raw 10k baseline/current and 100k current observations under `docs/validation/v0.2` | 25.7x on the specific same-host 10k workload; not vendor performance, database throughput or a production SLA |
| No approximate match grants approval | Existing engine tests plus `test_candidate_index.py`, including differential exhaustive retrieval checks | Finite test evidence, not a mathematical proof covering all inputs |
| Cross-project records and attachments are not authorized by a guessed ID/hash | `test_access.py`: lists, details, mutations, evidence, snapshots, release checks and scoped administrator cases | Application authorization; no multi-tenant persistence or independent security audit |
| A reviewed batch cannot silently apply to different state | `test_plans.py`: head/digest/version changes, atomic rollback, concurrency, foreign projects, status/approval injection | Proposal/amendment workflow only; no batch approvals or Git-merge-as-approval |
| A changed declared dependency invalidates impacted targets only | `test_context.py`: actual file changes, transitive inputs, graph/settings changes, unrelated inputs, deep graphs | Explicit graph, not automatically inferred RTL/netlist dependencies or completeness proof |
| Evidence can be checked without access to its original database | `test_attestation.py`, `test_cli_extensions.py`: bundle replay, tampering, external key/subject, expiration, checkpoint prefix and rollback | Requires trusted public-key distribution; not KMS, WORM, trusted timestamps or real EDA provenance |
| Native derivative does not hide the fixture's unapproved sibling | `scripts/native_verilator.py`; successful native CI artifact records actual tool version | Verilator fixture only, not Calibre/IC Validator/SpyGlass/Questa qualification |

## What would justify a broader superiority claim

Use legally available vendor installations and the same redistributable design/report corpus. Publish tool versions, PDK/rule-deck revisions, hardware, configuration, run completeness, runtime and memory, with no hidden preprocessing advantage. Independently label unchanged, moved, reshaped, split/merged, hierarchy-promoted, duplicated and truly new occurrences. Measure false suppression separately from review-candidate recall, ambiguity, reviewer effort and export scope. Never trade false suppression for a prettier match rate.

Run an independent penetration test and project-isolation review; restore signed backups and demonstrate rollback/rewrite detection with off-host retained checkpoints. Exercise real multi-user conflicts, operating-system/database limits, enterprise identity integration, migration and disaster recovery. Obtain representative production users and qualified proprietary adapters before claiming native signoff replacement.

These are **uncompleted evidence requirements**, not features disguised as completed work. The present defensible positioning is an open, inspectable cross-tool governance layer with measured improvements over its own baseline. It complements native verification engines; it has not demonstrated dominance over all closed-source alternatives.

## Cryptographic implementation reference

[PyCA cryptography's Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/) provides the standard signing and verification primitive. OpenWaiver adds a versioned, domain-separated purpose/sequence/digest claim. It does not implement a new cryptographic algorithm or claim certification of its envelope.
