# Reproducible release-assurance comparison protocol

## Evidence status, 2026-09-07

Commercial tools already have substantial native functionality. Siemens documents
hierarchy-aware automatic DRC waiver handling and preserved waiver records in
[Calibre Auto-Waivers](https://www.siemens.com/en-us/products/ic/calibre-design/physical-verification/auto-waivers/).
Its [pattern-matching explanation](https://blogs.sw.siemens.com/calibre/2015/05/05/how-to-use-pattern-matching-to-improve-automatic-waiver-management/)
explicitly discusses distinguishing acceptable patterns from modified errors.
Cadence documents coverage waiver/refinement management and reuse in
[vManager](https://www.cadence.com/en_US/home/resources/datasheets/vmanager-ds.html).
Synopsys describes large-scale native physical verification and implementation
integration in [IC Validator](https://www.synopsys.com/implementation-and-signoff/physical-verification.html).

These are vendor claims, not measurements by this project. Lack of public detail
about an enterprise feature is **unknown**, not proof it is absent. OpenWaiver 0.4's
contribution is an inspectable, vendor-neutral release contract, receipt authority,
risk budget and portable replay mechanism. No licensed product was benchmarked.
Do not label the product "better than all commercial alternatives" on this evidence.

## Pre-register the same workloads and decisions

Give each tested system the same immutable input manifest, check coverage,
reference findings and expert review outcomes. Include both normal workloads and
negative cases: missing required tool; partial report; old execution reimported
recently; identical revision label but changed design digest; altered rule deck;
changed policy; expired/withdrawn waiver; missing evidence; moved or ambiguous
finding; over-budget approved findings; conflicting/duplicate decisions; wrong
project; altered receipt or artifact; missing archive member; stale frozen dossier.

Use synthetic workloads for public reproduction, and separately approved,
redacted real-project workloads for adoption decisions. Do not publish foundry
materials, customer design files or restricted tool output without authorization.
Each vendor adapter must be qualified against the exact installed version and
native round-trip behavior. A generated text file accepted by our own parser is
not sufficient interoperability evidence.

## Measure outcomes rather than feature counts

The primary safety measure is **incorrect releases accepted**, with each failure
investigated individually. Also report legitimate releases incorrectly blocked,
changed/stale exceptions missed, unapproved findings suppressed by native exports,
reviewer time and corrections, and audit replay success without the originating
server. Keep confidentiality and deployment-isolation tests separate from interface
filters. Run human comparisons with independent reviewers and counterbalanced
order; do not substitute the number of automated tests for measured usability.

For performance, record end-to-end import, storage verification, assessment,
package creation and replay separately. Use identical hardware, tool versions,
limits and cache conditions; publish input counts/size, peak memory, all repetitions
and confidence intervals. Include dense repeated rules, large geometry and many
waiver revisions. The earlier 25.7x OpenWaiver engine-only result is **not** a
commercial comparison and must not be reused as an end-to-end latency claim.

## Acceptance statement

Publish a scoped statement only after collecting results, e.g. "on workloads X
and tool versions Y, system A reduced median review time by Z with zero observed
incorrect acceptances across N labeled cases." Zero observed errors is not proof
of universal safety. Report incomplete integrations and untested scenarios openly.
This repository currently supplies executable regression/native/browser checks,
not a completed comparative user study or chip-signoff certification.
