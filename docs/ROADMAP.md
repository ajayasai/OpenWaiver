# Positioning and qualification roadmap

## What this release is designed to improve

The project emphasizes a common governance layer across tool boundaries: explicit scopes, consistent expiry/review policy, immutable candidate comparisons, human-readable exports, portable evidence and fail-closed automation. These are design goals and implemented behaviors, not evidence that every commercial competitor lacks equivalent capabilities.

Siemens Calibre Auto-Waivers publicly describes recognizing, tracking and removing waived DRC results. Synopsys IC Validator publicly documents creating/importing/appending/reusing waivers using its PYDB flow. Those vendor-integrated capabilities establish a meaningful comparison baseline; an open-source governance UI is not a substitute for their qualified geometry engines or native tool support.

Primary references (consulted 2026-09-05):
- https://www.siemens.com/en-us/products/ic/calibre-design/physical-verification/auto-waivers/
- https://video.synopsys.com/icvalidator/detail/videos/ic-validator-technical-videos%3A-waiver-flow/video/5973786096001/02---waivers-using-the-pydb-utility?autoStart=true
- https://verilator.org/guide/latest/control.html
- https://www.klayout.de/rdb_format.html

No controlled head-to-head study, exhaustive current open-source survey, commercial license testing, foundry qualification or silicon signoff has been performed. There is no justified “better than all closed-source tools” claim.

## Required before enterprise/signoff adoption

1. **Vendor adapter qualification.** Official/versioned Calibre, IC Validator, Questa/SpyGlass, RDC, UPF, coverage and STA fixtures; native executable round-trip testing; strict compatibility matrix. Do not invent proprietary syntax.
2. **Real design-change evidence.** Dependency-cone hashes, netlist/object stability, hierarchical physical transforms, polygons with holes, unit conversion, split/merge detection and instance-level disambiguation. Measure false-suppression rate separately from candidate recall; target zero false suppressions in adversarial tests.
3. **Independent identity and audit.** OIDC/SSO, project-level authorization, trusted CI workload identities, external KMS signatures/timestamps, independently anchored or WORM audit storage, secure backup/migrations and retention policy.
4. **Scale and reliability.** Indexed relational storage/search, incremental audit verification with protected checkpoints, performance on millions of findings and long histories, load/race/fuzz tests, resource controls and disaster recovery drills.
5. **Controlled comparison.** Evaluate the same legally shareable golden reports, moves/reshapes, hierarchy refactors, ambiguous duplicates, expired bounds, policy edits, incomplete streams and approval races. Record false automatic suppression, candidate precision/recall, gate accuracy, reviewer effort, export fidelity and end-to-end p50/p95 latency. Publish scripts and exact tool versions, not marketing scores.

## Near-term usability improvements

Bulk proposals that never bulk-approve, richer evidence previews, per-project policy separation, revision manifests backed by real VCS attestations, bidirectional Git proposal workflows, larger register pagination, accessibility audit and offline API documentation assets. The existing plug-in hooks are a starting point, not a certified connector marketplace.
