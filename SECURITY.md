# Security and operational trust

OpenWaiver 0.1.0 is intended for a **trusted local workspace** or a carefully administered internal service. It is not a hardened multi-tenant SaaS service, regulatory evidence vault or signoff authority.

## Access boundaries

The API derives identities from server-configured SHA-256 bearer-token records. Roles are viewer, contributor, reviewer and admin. Reviewers must additionally be assigned to the waiver and independent of its creator/owner; the admin role does not bypass independent approval. API requests cannot supply their own acting identity. Tokens are random, printed once at creation and kept in browser memory. A browser refresh signs out.

Each token can read the entire workspace. Roles control mutations, not project-level visibility. Use a separate database/service for separate confidentiality domains. Do not expose the service to the public Internet. The default bind is loopback. Remote binding requires explicit `--allow-remote`, a TLS reverse proxy, restricted networking and `OPENWAIVER_ALLOWED_HOSTS`. There is no integrated SSO/OIDC, rate limiting, account recovery or token expiry. Delete a token record and restart the server to revoke it.

Filesystem/database administrators are trusted. CLI actor/role flags are attribution for trusted operators, **not** a substitute for authenticated reviewers. Someone with write access to the source code, database or token registry can bypass controls. Protect those resources with OS permissions. Generated registries use mode 0600 on POSIX; configure equivalent Windows ACLs.

The dashboard rejects cross-origin writes, does not enable CORS, escapes imported text, uses a restrictive Content Security Policy and does not use localStorage/sessionStorage. Evidence downloads are served as attachments with `nosniff`; uploaded files are never executed. These controls are tested, but not independently penetration-tested. Browser extensions and a compromised host remain outside the boundary.

## Input safety and limits

Reports: 32 MiB UTF-8; 250,000 findings maximum. Request bodies: approximately 33 MiB. Evidence: 5 MiB per attachment, 50 attachments per waiver. YAML: 4 MiB and nesting depth 40; duplicate keys and aliases are rejected. XML uses defusedxml to reject entity expansion. Unsupported report records cause an import failure rather than invisible data loss. Plug-ins are disabled unless explicitly enabled and execute trusted local Python code; they are **not sandboxed**.

Inputs may still consume significant CPU within these limits. There is no distributed quota enforcement. Attachment signature checks are not antivirus scanning. File hashes verify bytes, not the truth of engineering evidence. The source-root option is CLI-only, resolves symlinks, refuses paths outside the root, and hashes a whole source file; it does not analyze dependency cones or netlist topology.

## Audit and signatures

State mutations and SHA-256 audit events commit together in SQLite. Historical waiver records are preserved in their events. The verifier checks the chain, current records and attachment bytes. Preserve audit heads independently; otherwise an administrator could replace the database and recompute every hash. This is **tamper-evident, not tamper-proof/WORM** storage.

Bundle checksums alone do not authenticate the creator. Optional HMAC seals authenticate only to parties that possess the shared secret; they are not public-key signatures or non-repudiation. Keep HMAC keys outside the repository and preserve the expected manifest hash/head using an independently protected channel. Version 0.1.0 has no KMS integration or trusted timestamp authority.

## Verification boundary

A `complete` import is an assertion by the report producer. OpenWaiver cannot detect a deliberately filtered report or prove the tool executed every intended rule. The release manifest explicitly enumerates required streams; omitted streams are not checked. Freshness checks use import timestamps, not attested tool execution times. Revision strings are exact caller-supplied identifiers, not validated Git ancestry. Missing provenance fields cannot establish provenance.

Approximate matches never inherit approval. Duplicate or ambiguous identities block suppression. An approved waiver can become ineffective through expiry, context/provenance change, revision mismatch or changed policy. A waiver is not verification signoff, a safety justification, or proof that a timing/CDC/coverage exception is technically valid.

## Reporting

Do not upload proprietary reports, security tokens or chip data in public issues. For a security concern, contact the repository maintainers privately using the repository's configured security reporting channel when available. No private reporting endpoint has been provisioned by this source release. Until one exists, describe only a non-sensitive request for a private contact channel publicly.
