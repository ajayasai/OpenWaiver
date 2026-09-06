# Security and operational trust

OpenWaiver 0.3.0 is intended for a **trusted local workspace** or a carefully administered internal service. It is not a hardened multi-tenant SaaS service, regulatory evidence vault or signoff authority.

## Physical evidence and federation (v0.3)

See [the v0.3 operating and trust guide](docs/V0.3.md) for configuration and limits.
Federation verifies RS256 access tokens with administrator-pinned public keys,
exact issuer/audience and provisioned subject/client/project bindings. Token
roles, emails and project claims never create grants. Invalid JWTs do not fall
back to local tokens. This is not a browser OAuth login implementation or a
certified identity-provider deployment. Protect the federation file outside Git;
rotate keys and revoke subjects through atomic administrative updates.

Physical evidence is bound to the declared report, scope, revision, placement
and extraction recipe. Its coverage is limited to declared layers/windows;
retaining or signing a manifest does not prove the producer supplied complete
or truthful geometry. Native layout parsing has no arbitrary-script endpoint,
but compressed inputs can exceed Python-side byte budgets in native memory.
Run extraction in a CPU/memory-limited worker for untrusted inputs. Unsupported
shapes, transforms and ambiguous occurrences are rejected, not approximated.
Older records stay readable; do not downgrade a workspace after writing v0.3
physical records. Back up and validate migration before use.

## Access boundaries

The API derives identities from server-configured SHA-256 bearer-token records or explicitly configured, pinned-key federated access tokens. Roles are viewer, contributor, reviewer and admin. Reviewers must additionally be assigned to the waiver and independent of its creator/owner; the admin role does not bypass independent approval. API requests cannot supply their own acting identity. Locally issued tokens are random and printed once at creation. Tokens are kept in browser memory. A browser refresh signs out.

Tokens can carry exact project grants, timezone-aware expiration and revocation. All resource routes enforce project visibility as well as mutation roles. Legacy records without `projects` remain workspace-wide; migrate deliberately. `projects: []` grants nothing; null means unrestricted. File-backed registries reload on every authenticated request; invalid edited registries fail closed. Removing a record or marking it revoked takes effect on the next request. Project-scoped principals cannot administer global policy or download full-workspace audit bundles, even with the admin role.

Use separate databases/services for separate confidentiality domains: this is application-level access control, not tenant-specific persistence, encryption, resource quotas or per-project policy. Do not expose the service to the public Internet. The default bind is loopback. Remote binding requires explicit `--allow-remote`, a TLS reverse proxy, restricted networking and `OPENWAIVER_ALLOWED_HOSTS`. Interactive SSO/OIDC login, rate limiting and account recovery remain unimplemented.

Filesystem/database administrators are trusted. CLI actor/role flags are attribution for trusted operators, **not** a substitute for authenticated reviewers. Someone with write access to the source code, database or token registry can bypass controls. Protect those resources with OS permissions. Generated registries use mode 0600 on POSIX; configure equivalent Windows ACLs.

The dashboard rejects cross-origin writes, does not enable CORS, escapes imported text, uses a restrictive Content Security Policy and does not use localStorage/sessionStorage. Evidence downloads are served as attachments with `nosniff`; uploaded files are never executed. These controls are tested, but not independently penetration-tested. Browser extensions and a compromised host remain outside the boundary.

## Input safety and limits

Reports: 32 MiB UTF-8; 250,000 findings maximum. Request bodies: approximately 33 MiB. Evidence: 5 MiB per attachment, 50 attachments per waiver. YAML: 4 MiB and nesting depth 40; duplicate keys and aliases are rejected. XML uses defusedxml to reject entity expansion. Unsupported report records cause an import failure rather than invisible data loss. Plug-ins are disabled unless explicitly enabled and execute trusted local Python code; they are **not sandboxed**.

Inputs may still consume significant CPU within these limits. There is no distributed quota enforcement. Attachment signature checks are not antivirus scanning. File hashes verify bytes, not the truth of engineering evidence. The source-root option is CLI-only, resolves symlinks, refuses paths outside the root, and hashes a whole source file; it does not infer dependency cones or netlist topology. The separate `context-build` collector hashes explicitly declared dependency graphs, rejects symlink dependencies and enforces byte budgets. Missing graph edges remain missing evidence; it cannot prove completeness. Run the collector against an immutable checkout.

## Audit and signatures

State mutations and SHA-256 audit events commit together in SQLite. Historical waiver records are preserved in their events. The verifier checks the chain, current records and attachment bytes. Preserve audit heads independently; otherwise an administrator could replace the database and recompute every hash. This is **tamper-evident, not tamper-proof/WORM** storage.

Bundle checksums alone do not authenticate the creator. Optional HMAC seals authenticate only to parties that possess the shared secret; they are not public-key signatures or non-repudiation. Keep HMAC keys outside the repository and preserve the expected manifest hash/head using an independently protected channel. There is no KMS integration or trusted timestamp authority. Version 0.2 adds offline Ed25519 signatures over artifact digests and domain-separated ledger checkpoint claims. Verification requires an independently supplied public key and expected subject, checks expiration, and can reject checkpoints older than an externally retained minimum sequence. Keep private keys outside the workspace and repository. Signatures are not WORM storage, proof of tool execution, trusted timestamps or a substitute for independently retaining checkpoints. The HTTP API has no signing-key endpoint.

## Review-plan boundary

Git plans only propose or amend explicit records. Apply is atomic and requires the preview digest, current audit head, pinned record versions and target identities. Any amendment resets approvals. Arbitrary imported approval/status/evidence fields are rejected. A Git merge is not a waiver approval. Operators with local database or signing-key access remain trusted; CLI identity flags do not prove that a named human personally acted.

## Verification boundary

A `complete` import is an assertion by the report producer. OpenWaiver cannot detect a deliberately filtered report or prove the tool executed every intended rule. The release manifest explicitly enumerates required streams; omitted streams are not checked. Freshness checks use import timestamps, not attested tool execution times. Revision strings are exact caller-supplied identifiers, not validated Git ancestry. Missing provenance fields cannot establish provenance.

Approximate matches never inherit approval. Duplicate or ambiguous identities block suppression. An approved waiver can become ineffective through expiry, context/provenance change, revision mismatch or changed policy. A waiver is not verification signoff, a safety justification, or proof that a timing/CDC/coverage exception is technically valid.

## Reporting

Do not upload proprietary reports, security tokens or chip data in public issues. For a security concern, contact the repository maintainers privately using the repository's configured security reporting channel when available. No private reporting endpoint has been provisioned by this source release. Until one exists, describe only a non-sensitive request for a private contact channel publicly.
