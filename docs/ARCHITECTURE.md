# Architecture and invariants

```
Unfiltered documented exports
       | strict adapters + optional whole-file context hashes
       v
Immutable Run (project / stream / tool / revision / provenance)
       |                     |
       |              Waiver lifecycle service <--> authenticated API / browser
       |                     |                     <--> trusted CLI
       +--> pure assessor <--+
                |
    exact / changed / stale / ambiguous / unused / unobserved
                |
    per-run gate + explicit multi-tool release gate
                |
    frozen snapshots / SARIF / JUnit / YAML / evidence bundle

SQLite authority: runs, waivers, policy, snapshots, evidence, atomic audit chain
Git: deterministic human-readable projection, not a second mutable authority
```

## Identity versus evidence

The `ow1:` fingerprint hashes canonical JSON over the complete supported identity fields. Report row IDs are retained but excluded from fingerprints because tools may renumber results. Path separators and redundant path components normalize; path case, hierarchy conventions and basenames are never guessed. Message content and numeric values are not discarded. Metadata participates in identity, favoring conservative false-positive re-review over unsafe conflation.

Geometries retain units, layers, frames and all supported points. A box's corners are canonicalized. Edges are direction-independent; a polygon's cyclic start point and orientation are canonicalized with a linear-time minimum-rotation algorithm. There is no coordinate quantization, tolerance-based exact equivalence, unit conversion, polygon-hole interpretation or hierarchical transform inference. Different shapes sharing a bounding box remain distinct. Multiple geometry values are retained. KLayout aggregate multiplicity greater than one cannot be waived until instance-level disambiguation is supplied.

`context_hash` is separate from identity so an unchanged marker can explicitly become `stale` when its context changes. The optional source-root helper hashes the entire source file. External adapters may provide a design-context digest, but the collector is responsible for its meaning and completeness. A missing context across a revision boundary blocks reuse by default.

## Matching

Exact identities are indexed once. Scope isolation precedes matching. Exactly one current occurrence and one live waiver must correspond. An exact match still needs effective approvals, bounds, evidence, provenance and context. Duplicate occurrences are not deduplicated away.

Approximate candidate lookup indexes rule/category/hierarchy and explicit object IDs. Movement, source-message similarity and supported geometry shapes produce a candidate with reasons. A candidate is never a suppression. One-to-many/many-to-one correspondence is ambiguous. Candidate pools exceeding the configured budget are not searched partially and then represented as confident answers. Their waiver outcomes remain unobserved, not falsely unused.

A rebind explicitly selects the new target, updates its baseline and clears every approval. Rationale/evidence remain available for a fresh review. History retains the earlier target and decision.

## Lifecycle

```
proposed --submit--> submitted --quorum--> approved
   ^                    |                    |
   |                    +--reject--> rejected|
   +---------- amend / rebind ----------------+

owner/assigned reviewer/admin --revoke--> revoked (terminal)
```

Evidence must be attached before submission. Attachments and substantive edits reset approvals. Every approval binds a digest of the waiver's reviewed content. The creator and owner cannot approve; admin cannot pretend to be a different assigned reviewer. Approval quorum is reevaluated against the current policy. Optimistic record versions prevent lost updates, including concurrent votes and attachment operations.

Expiration dates are inclusive UTC calendar dates. An exact revision bound is valid only for that string; it is not a less-than comparison or Git ancestry rule. Supplying both date and revision requires both to remain valid. The default 90-day horizon is a policy choice, not a standards requirement.

## Persistence and recovery

SQLite uses WAL, a busy timeout and one connection per transaction. Mutations take `BEGIN IMMEDIATE`. State and events commit atomically; transactions roll back together. Historical waiver event payloads permit inspection of prior rationale, target, evidence and approval data. Snapshots retain their policy and assessed-on date. Cross-scope snapshot comparison is rejected.

Verification traverses the audit and stored data; large histories can dominate interactive latency. Database reads currently deserialize JSON records rather than using a full relational analytics schema. Candidate lookup is indexed in memory and output-state aggregation is linear rather than rescanning all findings for every waiver. These implementation details do not establish production-scale throughput; benchmark the complete workload before deployment.

There is no production migration framework beyond schema-version rejection in 0.1.0. Stop the service and back up the SQLite database consistently before upgrading. Do not copy only the database file while a WAL writer is running; use SQLite backup or a stopped/checkpointed workspace. Verify the audit head after restore and retain external checkpoints.
