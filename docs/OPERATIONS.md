# Review records, evidence and CI

## API workflow

Use `Authorization: Bearer TOKEN` on every `/api/*` request. Tokens resolve to server-side principals. Create a run (`POST /api/runs`), propose a waiver (`POST /api/waivers`), upload an evidence attachment, submit, and have a separately authenticated assigned reviewer approve it. Every waiver mutation after creation requires the currently displayed `version`; a stale edit returns HTTP 409. Bad input returns 400/422; unauthorized operations return 401/403. Integrity failures return 503 and must not be ignored.

Important routes:

| Route | Meaning |
|---|---|
| `GET /api/runs/{id}/assessment` | Full-run gate plus paginated/filterable finding detail; filtering never narrows the actual gate. |
| `POST /api/waivers/{id}/amend` | Change rationale, owner, reviewers or bounds; reset to proposed and clear approvals. |
| `POST /api/waivers/{id}/rebind` | Explicitly move a waiver to a new finding; same project/stream/tool and rule/category required. |
| `GET /api/waivers/{id}/history` | Historical records and decisions from committed events. |
| `POST /api/snapshots` | Freeze the exact policy, records and assessment; optional `require_clean`. |
| `GET /api/compare/{before}/{after}` | Compare two frozen same-scope candidates. |
| `POST /api/release-gate` | Evaluate every required manifest stream in a single consistent database read. |
| `GET /api/audit` | Verify state/history integrity and show recent events/head. |

List endpoints paginate. The dashboard finding explorer uses 100 rows per page. Its run/waiver register loads up to 1,000 records; use the paginated API/CLI for larger inventories. Before deploying at substantial scale, benchmark both the UI and full audit traversal.

## Git projection

`export-yaml NEW_DIRECTORY` creates one human-readable waiver YAML per UUID, policy YAML and a manifest with hashes and an audit checkpoint. Repeated exports of unchanged state have identical bytes. Exports refuse to overwrite an existing directory so stale files cannot accidentally remain in a supposedly complete set.

SQLite remains the authoritative lifecycle store. This is **not** bidirectional Git synchronization. Git protects reviewability only when your repository permissions, reviewers and branch protections are configured correctly. Importing editable YAML creates a new proposal and discards claimed approvals/status/evidence. Its target must match an existing immutable run. Previously exported approvals cannot be replayed as trusted new approvals.

Treat YAML as confidential design information. Open-source application code can be public while actual workspaces and evidence stay private. The default `.gitignore` excludes databases, workspaces and credentials. Review files before publishing; patterns alone cannot prevent every secret leak.

## Evidence bundles

```bash
openwaiver --db workspace/chip.sqlite3 --actor bob --role reviewer \
  freeze RUN_ID --name 'Candidate B' --require-clean
openwaiver --db workspace/chip.sqlite3 bundle SNAPSHOT_ID --output evidence.zip
openwaiver verify-bundle evidence.zip
```

Bundles include the frozen snapshot, report outputs, per-waiver records, evidence bytes, audit events and a content-hash manifest. Deterministic ZIP metadata makes unchanged captures reproducible. Use `--key-file` on both bundle and verification for optional HMAC protection, or independently preserve `--expected-manifest`. A key file should contain securely generated random bytes and remain outside the project. HMAC requires shared-secret trust and does not identify a unique signer.

`openwaiver audit --expected-head HASH` checks an externally preserved checkpoint against the current database. A mismatch after legitimate later events is expected; maintain dated checkpoint records and the corresponding backups. A checksum without an independently trusted head does not protect against full database replacement.

## Release requirements

A manifest names the exact project/revision and required stream/tool/category combinations. Optional expected tool version, rule-deck digest and configuration digest are checked. When multiple runs match a required scope, pin a `run_id`; the tool does not cherry-pick a passing older run. Every required check must pass. Unlisted checks are outside the gate's coverage.

Use unfiltered outputs. Native derivative control files can suppress more broadly than a fine-grained lifecycle record; never assess only a filtered result and claim it proves clean raw verification. Store manifests, report-producer configuration and revision IDs under protected review. The application cannot independently attest a tool invocation or reconstruct omitted violations.

## Container deployment

Docker assets are included but have not been executed in the local release validation. The image runs as UID/GID 10001 and binds to the host's loopback through Compose. Generate a registry on the host first. For Linux bind-mount permissions, make a dedicated container copy rather than changing ownership of the registry used by local CLI workflows:

```bash
cp workspace/auth.json workspace/container-auth.json
sudo chown 10001:10001 workspace/container-auth.json
sudo chmod 600 workspace/container-auth.json
docker compose up --build
```

Keep the named data volume and the registry copy private. Repeat the registry-copy preparation and restart after rotating tokens. Docker Desktop filesystem semantics may differ; verify ownership/readability rather than making the registry world-writable. A remote deployment still needs TLS, network restrictions, backups and properly configured allowed hosts.

HMAC key files must contain at least 32 bytes; empty or short keys are rejected rather than reported as authenticated. Bundle audit history ends at the committed snapshot event, so later lifecycle edits do not change a previously frozen bundle's bytes.
