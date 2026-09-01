# Kingphisher-Phoenix — Operator Runbook

Operational runbook for the threat-informed phishing-awareness platform. Covers
installation, daily operation, monitoring, troubleshooting, and recovery. Daily
campaign and local lifecycle work is console-driven. Initial installation,
Azure tenant bootstrap, protected release qualification, and several
tenant-administrator actions still require scripts or provider consoles; those
gaps are identified below rather than presented as GUI-complete.

Quick links: [Architecture](docs/architecture/README.md) ·
[AI handoff](docs/AI_HANDOFF.md) · [QA findings](QA_TASKS.md)

> **Wave 38 operator alignment.** This deployment serves one 125-person tenant
> operated by two IT staff. `ORG-001`, `THR-001A`, and `DOCSIM-001` are complete
> locally. One independent operator holding both approval capabilities may
> complete the separate security and privacy approval facets; campaign
> self-approval and all RoE/audience/canary/provider/stop/review safety bypasses
> remain forbidden. `IMP-001` and `THR-001B` are complete locally with guided,
> serialized CSV import and the bounded explicit-curation Threat Campaigns
> workbench. `OUT-001`/`RET-005`/`INT-001` retention integration is complete at
> Alembic head `0032_source_explicit_curation`: confirmed interaction,
> terminal-only project-before-purge, current outcome-writer locks, stable
> pseudonym configuration/grants, a 365-day raw maximum, and a PII-free
> 1,826-day ledger are wired. Privacy/RBAC, named-history API, reporting/graph,
> and export consumers remain open. Independent review found no P0 and one P1:
> ORM `RetentionPolicy.__table_args__` must mirror migration `0032`'s retention
> check and single-default index. That statement is historical: as of
> 2026-08-31 the tree is committed and pushed at `40c611d`, with every
> non-operator gate passing head-exact (hermetic 2707, external PostgreSQL 92,
> Redis 2, fresh-migration 1, E2E 8/8, exact-final ARM64 at `2adb2a2`). Use the
> continuation prompt in `RESUME-HERE.md`.
>
> Deferred functionality remains retained and supported without expansion.
> Never delete potentially valuable features merely because they are deferred.
> The AI deployment target is a benchmark-selected, digest-pinned `llama.cpp`
> model in the existing worker role/job, CPU first; scale-to-zero serverless GPU
> is measurement-gated, Foundry serverless/token inference is optional, and
> Foundry managed compute/always-on GPU is out of scope. `.140` is
> development/qualification infrastructure only.

> **Release status (2026-08-29): NO-GO for production and RSA Conference.**
> The pre-remediation local and external operational-readiness snapshot reached
> head `0029` and passed 2,329 hermetic/97 deselected, 86 PostgreSQL/2,340
> deselected on Redis DB14, 2 Redis/2,424 deselected on DB15, and 8 E2Es plus
> audit and installation verification; its 03Z log window was clean. The
> pre-Wave-36 local hermetic `make test` passed 2,469 tests/97 deselected with 0
> failures in 158.15 seconds. At checked-in head
> `0030_default_privacy_notice`, the final local Wave 36 hermetic suite passed
> 2,501 tests/97 deselected with 0 failures in 183.40 seconds. PostgreSQL, Redis,
> Current-head `0032` PostgreSQL/Redis/E2E external profiles and exact-image
> evidence remain open.
> Browser/WCAG, full recovery, exact-final
> images, AMD64/registry, remote Terraform/Azure execution, and live
> Entra/Graph/ACS/Outlook qualification remain incomplete.
> No current custom-domain/certificate and edge
> evidence, backup/restore exercise, rollback workflow, or end-to-end
> ACS/Microsoft 365 evidence has been recorded. Use only a disposable local
> environment or an explicitly non-production staging tenant.

## 0. Current engineering topology

The controller workspace is
`/Users/edierks/projects/codex-test/phishing-awareness-platform`. The target
native ARM64 worker is `edierks@192.168.1.140`, with canonical source
`/Users/edierks/Projects/kingphisher-phoenix` mounted read-only inside the
project-only `kingphisher` Colima VM. Its VM disks, cache, Docker client
metadata, and socket are beneath
`/Volumes/DockerExternal/KingPhisher-Phoenix` on the attached 1 TB
`DockerExternal` drive. Run the read-only controller preflight before work:

```sh
scripts/operator/remote-docker-worker/preflight.sh
```

Every project command must select the exact external socket
through `external-engine.sh` or explicit inactive `kp-external-mac`. That
context endpoint is exactly
`ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
and reports `colima-kingphisher|aarch64|/var/lib/docker`;
the default remains `desktop-linux`. The external profile/socket and read-only source
mount passed preflight. The remote
global context stays `desktop-linux`. Docker Desktop on `.140` is a separate
shared engine with unrelated workloads; never move it, use it as fallback,
change the global context, or stop/prune/remove any unrelated resource. Mount,
UUID, writability, path, profile, credential-policy, source, or capacity drift
blocks. Rosetta and binfmt are disabled. See the
[external-worker procedure](scripts/operator/remote-docker-worker/README.md).
The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can resolve to shared Docker Desktop; never use them
for project operations. The external volume with the `DockerExternal` label
remains the required storage target.

Loopback URLs in this runbook refer to the machine running the application. The
seven internal Docker Desktop project containers are stopped and preserved
(and as of 2026-08-31 the duplicate stack on the controller Mac is stopped too,
containers and volumes preserved, so `.140` is the only running engine);
unrelated containers remain running. Browse on `.140` or
establish an SSH tunnel. Never expose the Docker API over TCP. Preserve the
external profile and stopped internal rollback copy. The legacy encrypted
snapshot has no available identity, is unrecoverable, and does not satisfy
`EXT-002`. The USB/HFS+ worker is unencrypted and lacks SMART
telemetry, so it is engineering infrastructure using synthetic or explicitly
approved test data—not the Azure production runtime.

The controller recovery identity is verified at public recipient
`age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2`.
Headless SSH cannot unlock the remote login Keychain, so create the fresh
checkpoint only through `checkpoint-remote.sh`, which transfers and cleans up a
temporary identity. After apply, use controller `stage-remote.sh` to invoke
`stage-checkpoint.sh` with a second temporary transfer and validate the exact
archive and publish its `migration-checkpoint/` payload without clobbering
existing state, then invoke `restore-state.sh` through the external-engine
helper. Snapshot `20260829T013332Z-tsX1WQ` (SHA-256
`e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`)
passed staging and restore: 39 tables, Redis DB0 766→766 and DB15 12→12.

The cold-start timeout repair is locally validated by 42 tests: 900-second
default, 3600-second maximum, and strict input validation. It is synced and its
non-mutating remote `--check-uv` prerequisite passed; no cold full rerun under
the new default is claimed.

The pre-remediation local and external operational-readiness snapshot reached exact migration
head `0029`: 2,329 warning-strict hermetic tests passed with 97 deselected;
PostgreSQL passed 86 with 2,340 deselected while isolated on Redis DB14; Redis
passed 2 with 2,424 deselected on DB15; audit and `verify_install` passed; and
the live local E2E profile passed all 8. Its 03Z API/worker log window
contains no error/critical event and no unknown-campaign or unknown-pattern job.
Ruff/format over 336 Python files, strict mypy over 124 source files, Bandit,
Semgrep over 4 rules/125 targets with 0 findings, Trivy repository scans with 0
HIGH/CRITICAL vulnerabilities, secrets, or misconfigurations, pip-audit with no
known vulnerabilities, Actionlint, and Zizmor are green. The final local Wave
36 hermetic `make test` passed 2,501/97 deselected with 0 failures in 183.40
seconds. The earlier 2,469/97 result is pre-Wave-36 history. PostgreSQL, Redis,
and current-head `0032` external profiles have not yet superseded the
pre-remediation snapshot. Historical Wave 18–21 snapshots and exact
commands remain labeled in the build plan. Final local acceptance also exposed
and fixed an audit-store owner-fallback revocation defect, reconciled 36
stranded idempotent queue intents, and ended with a green audit chain. Earlier controller observations at
approximately 5.9 and 5.6 GiB are historical evidence that deployment and
release-image gates stopped safely. Capacity work now runs on the isolated
external worker, whose exact preflight reports approximately 744,006,440 KiB
free. Later source edits through Wave 38 make the interim native ARM64 images
stale; exact-final rebuild/rescan has not yet been claimed. Browser/WCAG,
AMD64/registry, protected GitHub environment/configuration and final-source sync,
remote Terraform/Azure execution, live Entra/Graph/ACS/Outlook, full recovery,
and witnessed operation remain unqualified.

An exact-final ARM64 pass requires evidence proving the exact Docker server platform
without emulation, use explicit `--platform`, record OS/architecture/image-ID
metadata for all five images, prove source and context manifests did not change,
scan with Trivy 0.74.0, retain no-clobber `qualification.json` plus scan evidence, and verify cleanup only for
labeled disposable resources. The verifier also requires the expected
source-manifest digest, exact Trivy executable/hash/cache, retained empty config/ignore/secret policy files, rejection of ambient
`TRIVY_*`, fresh database/check-bundle metadata, and an immutable verified cache.
The Azure workloads stage separately scans each
exact immutable ACR `repository@sha256` subject with pinned Trivy before SBOM,
attestation, or deployment and retains scan JSON and checksums. This is the
required procedure; only the retained evidence can establish the result.
The planned authoritative root is
`/Volumes/DockerExternal/KingPhisher-Phoenix/qualification-evidence/arm64-release-20260829-wave35-final-v3`
with verifier evidence under `verifier/` and unique prefix
`kingphisher/verify-arm64-20260829-w35-final-v3`; the path alone is not a pass.
The preserved `final-v2` attempt failed closed before image build because BSD
filesystem-mode and evidence-path/source-context defects violated the verifier
contract. Its failure evidence remains preserved. The repaired `final-v3`
attempt is evidence-conditional until its retained `qualification.json` and
per-image scan/checksum artifacts validate.

The latest complete external PostgreSQL gate remains the historical 86-test
result with fresh/historical migration coverage at exact head `0029` (`0028`
exact campaign-training binding and `0029` reviewed-canary launch gate). The
checked-in chain now adds `0030_default_privacy_notice` and
`0032_source_explicit_curation`; no current-head `0032` external migration
qualification is claimed. Earlier targeted `0025`→`0026`
evidence remains relevant: legacy oversized training rows were preserved, new
oversized writes were rejected, and the runtime role could update only
`training_resource_id`. Fixture/schema/role/engine cleanup leaks found during
qualification were repaired.

PostgreSQL integration tests must use `REDIS_URL_POSTGRES_TEST` on Redis DB14.
The gate validates that isolation and flushes only DB14 immediately before and
after its profile. The Redis queue contract remains isolated on DB15. Never use
application DB0 for a test profile or cleanup.

---

## 1. Installation

### 1.1 Prerequisites

- 64-bit **macOS** (Apple Silicon or Intel) or **Debian/Ubuntu Linux**.
- A working internet connection (package downloads, Docker images, PyPI).
- For `git clone` over SSH: an SSH key added to your GitHub account.
- 8 GiB available on the project filesystem by default. The one-click paths
  check this before dependency synchronization or infrastructure startup.

### 1.2 Installer prerequisites and managed dependencies

The installer does not bootstrap a package-manager trust chain. Provide `git`,
`curl`, `openssl`, and `uv` first; install `uv` with a trusted package manager.
The script deliberately does not execute a downloaded shell installer. Docker
can be installed by the script when dependency installation is enabled.

| Dependency | Where | Notes |
|---|---|---|
| `git`, `curl`, `openssl` | operator-provided | required and checked; the installer does not install them |
| `uv` 0.11+ | operator-provided trusted package manager | required; manages Python and project packages |
| Python 3.13 | via `uv sync --frozen --all-packages` | project interpreter in `.venv` |
| Docker CLI + Compose plugin | installer when missing: Homebrew/Colima (macOS) or apt/systemd (Linux) | requires Homebrew on macOS or sudo on Linux |
| Docker daemon | Colima VM (macOS) / `docker.io` systemd service (Linux) | started automatically; first Colima start downloads a VM image |
| All Python packages | `uv sync --frozen --all-packages` | uv workspaces (`apps/*`, `packages/*`); normal bootstrap/development/console launch never mutates `uv.lock` |
| Infrastructure images | `docker compose up -d` | PostgreSQL, Redis, Mailpit, OTel, and the mock Python base are pinned by tag plus immutable manifest digest; mocks are built locally |
| macOS launcher app | `scripts/build_launcher_app.sh` | creates `Kingphisher Launcher.app` (double-clickable) |

On a standalone macOS development host, an existing Docker Desktop daemon may
satisfy the generic installer. That rule does not apply to the designated
`.140` worker: its Docker Desktop engine is shared and prohibited as project
fallback. On `.140`, use only §0 and the external-worker helper; never run
`brew services start colima`, which can omit the external home and create an
internal default profile.

The mock Python runtime uses a fully pinned, hash-verified 17-package lock. To
verify the production workspace dependency closure, run `make
security-scan-dependencies`; it exports the frozen non-development closure with
hashes and fails closed if export or audit fails. `make sbom` emits CycloneDX
1.5 with 59 total components, including 58 external package PURLs. These are
dependency/static controls, not proof of an application-image rebuild.

### 1.3 Fresh install

```bash
git clone git@github.com:ELDSRQ/kingphisher-phoenix.git
# or: git clone https://github.com/ELDSRQ/kingphisher-phoenix.git
cd kingphisher-phoenix
./scripts/install.sh
```

What runs, end to end:

1. Detect the OS, validate prerequisite tools, and require 8 GiB of free disk
   by default before dependency synchronization or infrastructure startup. A
   different `KP_LOCAL_MIN_FREE_GIB` must be a positive whole-GiB integer.
2. Install Docker if needed (see §1.2) and prove bounded Docker/Compose access.
3. Before dependency synchronization or any `.env` write, inspect preserved
   volume identity and validate every existing recovery key, cross-service key
   mirror, console JWT, Mailpit credential, and console credential. Missing or
   inconsistent recovery material around existing or uninspectable state stops
   the installer without generating replacements.
4. Create the project virtualenv (`uv sync --frozen --all-packages`), then
   generate `.env` secrets once for a proven clean installation (`.env` is
   gitignored; never commit it):
   `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`,
   `OPERATOR_API_AUDIT_HMAC_KEY`, `OPERATOR_API_CIPHERTEXT_KEK`,
   `OPERATOR_API_CONSOLE_JWT_SECRET`, `OPERATOR_API_RECIPIENT_HASH_SALT`,
   `TRACKING_TOKEN_HMAC_KEY`, `MAILPIT_API_PASSWORD`, `KP_CONSOLE_PASSWORD`.
   DSN/REDIS_URL lines are rewritten to embed them.
   Existing values are preserved on re-runs (idempotent).
5. Run `deployment-preflight` in read-only `prestart` mode. It permits either a
   clean first deployment or the complete expected named-volume identity and
   blocks partial, missing, renamed, or mismatched preserved state.
6. Qualify the digest-pinned PostgreSQL and Redis images for the selected host
   platform. Hardened ephemeral probes require non-empty account/entrypoint
   files and a working service version command; they do not attach project
   volumes.
7. Start only missing infrastructure with Compose `--no-recreate`: Postgres
   `:5432`, Redis `:6379`, Mailpit `:1025/:8025`, mock-idp `:8443`, mock-graph
   `:8181`, mock-ai `:8282`, and OTel `:4317/:4318`.
8. Apply DB migrations (`alembic upgrade head`), reconcile the audit root, and
   seed a reproducible demo dataset (idempotent), then run the read-only `ready`
   preflight to require healthy stateful services and the current migration head.
9. Build `Kingphisher Launcher.app` (macOS only) through staged publication;
   an unchanged bundle creates no backup, and failed publication restores the
   previous bundle.
10. Start the operator API `:8000`, tracking API `:8001`, and eight workers under
   `scripts/supervisor.py`.
11. Require both a live supervised PID and `/readyz`, then print the console URL
   and open it. The password is not printed.

Any failed deployment/recovery gate leaves existing containers, named volumes,
databases, credentials, and recovery evidence in place and tells the operator
what evidence to inspect or what capacity to add. It never authorizes deletion,
pruning, or a fresh volume as an automatic repair.

> Read the local console password from `.env` (`KP_CONSOLE_PASSWORD`). The
> installer intentionally does not copy it to terminal or log output. Treat it
> like a root password — anyone with it can operate (and audit-trail) the local
> platform.

### 1.4 Re-runs and manual starts

- `./scripts/install.sh --skip-deps` — re-provision on an already-provisioned
  machine (skips OS-level dependency install).
- `./scripts/run_console.sh` — GUI path without the installer: bootstraps
  `.env`, starts infra, migrates, seeds, starts the stack, opens the console.
  Refuses to double-launch if the supervisor is already running; that fast path
  opens the console without repeating startup gates.
- Make targets (dependencies already present):

  ```bash
  make bootstrap        # uv sync + compose infra + db init
  make seed             # idempotent demo dataset
  make dev              # operator-api + tracking-api in the foreground
  make verify-install   # health-check a running install
  ```

`make seed` is intentionally a source-checkout command; there is no installed
`kp-seed` executable. To sign an already published immutable image, use
`IMAGE=registry/path@sha256:<64-lowercase-hex> COSIGN_KEY=<key-reference> make sign`.
The target fails closed if either value or `cosign` is absent. No external
signature has been produced or verified for the current build.

### 1.5 Verifying an install

```bash
./scripts/verify_install.sh   # infra health, API readiness, console auth, worker pidfiles, audit chain
make verify-audit             # recompute and compare the audit hash chain
make operational-readiness    # complete disposable-local release/readiness gate
```

`operational-readiness` is a disposable-local qualification gate, not Azure or
production evidence. It requires at least 2 GiB free and a provisioned local
stack. That is distinct from the one-click installer/launcher's earlier 8 GiB
default deployment headroom gate.
The latest installation verification is green after restart, and the live local
E2E profile passes all 8 tests. The same acceptance reconciled 36 stranded
idempotent queue intents after fixing the audit-store owner-fallback revocation
defect; final audit-chain verification is green. Those repairs do not constitute
a full backup/restore exercise. Static accessibility-shell contracts pass. Full
browser/WCAG automation and human assistive-technology acceptance remain
separate, open release gates.
It validates Compose configuration and migration heads, runs lint (including
console JavaScript syntax), type checking and tests, verifies the audit chain,
checks live services/workers, and performs an authenticated HTTP smoke of the
console. Outside its isolated lifecycle campaign, it does not migrate, seed,
deliver, delete, restart, or stop services. The gate requires `uv`,
Docker/Compose, curl, Node, a populated `.env`,
and the full stack already running. Tests must use a separate
`DATABASE_URL_TEST`; the script fails if it matches the application database.
The E2E stage uses seeded approved pattern/template records and creates one
uniquely named campaign with the local administrator. It adds a local web-alert
subscription and schedules the campaign
24 hours ahead with `max_recipients=1`; it never contacts an external alert
provider. Lifecycle mutation is hard-limited to loopback, `dev` authentication,
and `single_tenant` deployment mode, so run the gate on a disposable local DB.

---

## 2. Operating the platform

### 2.1 Launch

- macOS: double-click `Kingphisher Launcher.app`.
- Any platform: `./scripts/run_console.sh` (or the installer).

Open `http://127.0.0.1:8000/console` and log in with `KP_CONSOLE_PASSWORD`
from `.env`.

### 2.2 Console screens

| Screen | What you can do |
|---|---|
| Dashboard | live status pills (operator/tracking API, Postgres, Redis, each worker), campaigns, audit verify |
| Campaigns | create/edit campaigns from a pattern, preview, approve workflow, recall, and scoped kill switch on eligible campaigns |
| Recipients | browse bounded server pages, CSV import (see §2.5), explicit test-account designation, and capability-gated global/campaign exclusion history and lifecycle |
| Sources | create `rss`, `stix`, or `bulk_download` sources; record/revoke current terms; enable, disable, and request ingestion |
| Patterns | list lure patterns and approve for use; approval records a durable generation request, while queue/provider completion remains asynchronous |
| Template review | safely preview and approve or reject AI-generated drafts before use; review-only access does not grant authoring or cloning |
| Training lessons | create bounded text lessons, submit authored drafts, independently approve/reject pending lessons, and supersede approved lessons; buttons use server-derived per-resource authority |
| Privacy | view the persisted current privacy notice, submit data-subject requests (CCPA), verify, export (`access_export`), fulfill (`deletion`); notice-load failure warns without disabling request operations |
| Audit | hash-chained event log, "Verify chain", global kill switch with engaged-state indicator |
| Setup wizard | guided OIDC, Graph-compatible directory, SMTP, reported mailbox, AI, training, and webhook wiring with connection tests |
| Azure deployment | guided Azure, Entra, DNS, email-residency, private-runner, and Terraform-state preparation with validation and configuration export |
| Help | searchable plain-language setup topics and definitions for every aggregate-read operator role |
| Settings | local masked `.env` editor (blank a secret to keep it), Reload, Restart services; managed Azure is read-only here. Full shutdown is deliberately not remotely exposed |

### 2.3 First-run setup wizard

The console redirects administrators to **Setup wizard** until required local
or production connections are configured and the review step is completed.
The wizard explains why each connection is needed, labels required and optional
fields, lists prerequisites, provides examples, and shows where each value is
found in the provider's administration screens. Constrained settings such as
authentication mode and SMTP TLS use explicit choices instead of free text.
Changed connections are tested automatically before the wizard saves and
continues; the separate **Test connection** action remains available for
troubleshooting. The searchable **Help**
view defines provider terminology; for example, OIDC (OpenID Connect) is the
standard used to sign operators in through the organization's identity provider.
Non-secret values are prefilled from `.env`; secret fields are always blank and
leaving an existing secret blank preserves it. Connection tests use three-second
bounds, do not follow redirects, never include response bodies in results, and
do not persist transient values. The wizard automatically mirrors training URL
and domain settings into both operator and worker namespaces.

Each step also offers an AI setup assistant. It is advisory: secret fields and
credential-like text are removed before a request leaves the operator API,
suggestions are constrained to non-secret fields in the current step, and the
operator must explicitly apply, test, and save every suggestion. If the configured
AI provider is unavailable, the API returns deterministic local guidance. Common
safe questions about locating values, permissions, and failed tests are available
directly in each step. Prompts
and answers are neither persisted nor written to the audit log.
Provider responses are streamed with declared and decoded byte limits before
UTF-8/JSON/schema validation. Duplicate or malformed lengths, oversized bodies,
and unbounded fields fail with a stable error; response bodies, tokens, and
provider exception text are not returned or logged.

Operational alerts support generic signed webhooks and ntfy. For ntfy, allowlist
the service hostname (for example, `ntfy.sh`), then create a campaign alert
subscription with channel `ntfy` and an HTTPS topic URL such as
`https://ntfy.sh/my-disposable-random-topic`. The worker translates campaign
events into ntfy's JSON publish format. This initial integration deliberately
does not forward authentication credentials; use it only with a disposable,
unguessable test topic and never put credentials in the URL.
The console lists the signed-in owner's campaign subscriptions and disables
them explicitly; it does not expose another owner's destination. External
destinations require HTTPS, no embedded credentials, and a hostname in
`OPERATOR_API_ALERT_DESTINATION_ALLOWLIST`. `web` subscriptions do not accept a
destination URL.

Optional Graph directory sync is available afterward from **Recipients → Sync
connected directory**. The directory worker bounds pages/users, validates the
Graph-style schema, salted-hashes mailbox lookup keys, encrypts identity fields,
and audits counts without recording identities.

The local fallbacks require no external credentials. A non-Azure deployment may
need OIDC, SMTP, Graph-compatible, AI, and mailbox credentials. Azure uses Entra
and workload managed identities with ACS Email rather than SMTP credentials;
Microsoft 365 directory/mailbox permission grants remain tenant-admin work.
Restart services from the wizard only on the local `env_file` runtime. Managed
Azure configuration changes require reviewed Terraform/release configuration.

### 2.4 Campaign lifecycle (as an operator)

How a draft reaches recipients depends on the **approval policy**
(`OPERATOR_APPROVAL_POLICY`, shown as a banner at the top of the Campaigns
screen). See §2.8.

1. **Create** a campaign from an approved pattern and select one exact approved
   training lesson (DRAFT).
2. **Submit for approval** → PENDING_APPROVAL.
   - Under `enforce`: both a **security** and a **privacy** approval are
     required as separate recorded facets. One independent operator holding
     both capabilities may complete both; the campaign creator may complete
     neither. The console only offers "Schedule" once both facets are satisfied.
   - Under `single-admin` (the offline stack only): one administrator may
     schedule a draft directly, and the console offers "Schedule" on the draft.
3. **Review launch** — lock one immutable launch review over the exact campaign
   configuration, signed RoE, frozen audience, canonical template, approved
   lesson, and server-designated test accounts. Drift requires a new review.
4. **Schedule canary** — schedule queues only the locked test-account cohort;
   it does not prepare or send the full audience. The worker rechecks the exact
   review before provider I/O. Recipients outside
   `KP_ALLOWED_RECIPIENT_DOMAINS` are skipped and recorded as failed with the
   reason `domain_not_allowed`; the worker re-checks both the approvals and the
   allowlist per batch, so a message queued before a policy tightened cannot go
   out under the old rules. SMTP-like canaries require provider acceptance;
   ACS canaries require authenticated delivered receipts bound to the unchanged
   review and provider configuration.
5. **Publish full audience** — use the separate GUI action only while the exact
   canary evidence is current. Missing, failed, expired, or drifted evidence
   blocks publication, and the worker rechecks again at assignment boundaries.
6. **Monitor** the dashboard; use the **kill switch** (global, or scoped to a
   campaign) to revoke queued deliveries and tracking tokens immediately.
7. **Report** — the Report button shows aggregate funnel and operational
   evidence, send states, failures, and explicit denominators. Named outcomes
   are requested only for `view_named:results` and are limited to the first
   server-bounded page; aggregate-only users never receive them. CSV actions
   require `export_bulk:results`, use same-origin authentication, and enforce a
   bounded CSV response. Open/click/report rates are a share of *delivered*, not
   of recipients.
8. Outcomes are COMPLETED / EXPIRED. Raw delivery/tracking evidence follows the
   active retention policy (at most the current 365-day window); the separate
   PII-free awareness ledger is designed for 1,826-day retention. Its worker,
   privacy/RBAC, API, and reporting integration is still in progress.
   Assignments still QUEUED
   `KP_WORKER_QUEUED_STALE_HOURS` after a campaign closed are settled to FAILED
   with the reason `stale_queued_reconcile` — never silently re-sent.

For the no-credential local path, messages are captured by Mailpit at
`http://127.0.0.1:8025/`. Seeded messages use their unique tracking click URL;
the tracking API records the event, creates or reuses the recipient assignment,
and redirects with a distinct purpose-bound lesson credential. Assessed lessons
reject a missing or incorrect knowledge check and complete idempotently after a
correct answer. Assignments use a fixed 72-hour due policy; the formerly exposed
reminder-delay setting was ignored by runtime and has been retired. The latest
external 8-test E2E run at head `0029` included the loopback-only `example.com`
canary and proved one canonical
approved-template message across duplicate processing, open/click deduplication,
assignment reuse, separate open/completion purposes, knowledge-check
remediation/pass/replay, and correlated report/audit state before exact canary
cleanup. The test binds the durable reviewed-canary evidence gate. This is local orchestration
evidence only—not DNS, provider transport,
inbox placement, reading, or Microsoft 365 reporting proof. Previously delivered
messages retain the URL embedded when they were rendered, so create a new
campaign after changing delivery or training-link configuration.

### 2.5 Recipient CSV import format

`POST /api/v1/recipients/import` with `{"csv_text": "...", "department": "..."}`
(what the console sends):

The current basic endpoint remains supported. The guided header-mapping,
masked-preview, dedupe, merge/deactivate, bounded-error, and audited-count GUI
workflow is `IMP-001` and is complete locally; do not describe it as live
PostgreSQL- or production-qualified until the current-head profiles pass.

```
mailbox,display name,department
alice@example.com,Alice Example,Engineering
bob@example.com,Bob Example,
```

- Column 1 (required): mailbox; invalid rows are reported per-row, the rest import.
- Rows outside `KP_ALLOWED_RECIPIENT_DOMAINS` are **blocked**, counted
  separately, and listed individually in the import result. With the allowlist
  unset, import is refused outright under OIDC and allowed with an audited
  warning on the offline dev stack.
- Column 2: display name (falls back to mailbox). Column 3: department (falls
  back to the `department` field).
- Mailboxes are salted-hashed (`OPERATOR_API_RECIPIENT_HASH_SALT`); identity
  fields use direct application-layer AES-256-GCM with an authenticated format
  version and key ID. This is not envelope encryption.
- The recipient table requests 100 rows at a time and uses Previous/Next server
  pages. Campaign named reporting requests at most 500 rows and displays the
  server total/truncation state; neither surface downloads an unbounded list.
- Operators with `manage:exclusions` may add a required-reason global exclusion
  or a selected-campaign exclusion, optionally with a future expiry. Revocation
  requires a second explicit confirmation and reason; it timestamps the same
  record instead of deleting history. Expired or revoked rows no longer block
  future audience preparation. Users lacking that capability neither fetch nor
  render exclusion history.

### 2.5.1 Source governance

A source starts disabled. Before **Enable** or **Ingest**, record the current
terms acknowledgement in **Sources**, including the reviewed permission facts
and bounded review dates. Revocation disables the source. The API checks terms
when work is queued, and the worker checks again before fetch and under the
post-fetch database lock; a revoked, expired, incomplete, mismatched, or replaced
acknowledgement causes a no-write stop. Disable/revoke cannot cancel provider I/O
already in flight, so the post-fetch fence is the authoritative write barrier.

### 2.5.2 Training lesson governance

Training lessons are bounded plain text. The creator may submit only their own
draft; a different principal with review authority may approve/reject a pending
lesson or supersede an approved lesson. The API derives `can_submit` and
`can_review` from role, identity, and state on every list/preview/mutation
response. The console does not reconstruct those decisions and removes actions
if either flag is missing or malformed. Supersession prevents new selection but
does not rewrite immutable assignments already bound to that version.

### 2.6 Data-subject requests (CCPA)

Privacy screen → submit request (type, requester mailbox, optional campaign).
State machine: **opened → in_progress → completed** (45-day SLA deadline shown).

Checked-in migration `0030_default_privacy_notice` reconciles legacy duplicate
current rows, persists a safe default only when no current notice exists, and
adds the unique partial index `uq_privacy_notices_single_current`. The console
loads requests and the notice independently: a notice failure is visible as a
warning, but request listing and mutation remain available.

- `access_export` → Export button downloads the subject's record set.
- `deletion` → Fulfill deletes the subject's data and marks it completed.
- Every transition is audit-logged; deletion fulfills also purge tracking events.

### 2.7 Kill switch

- **Global:** Audit screen → **Engage global stop** (requires a reason and a
  second confirmation). It persistently blocks scheduling/delivery across
  replicas and restarts, cancels every queued assignment, and revokes every
  active tracking token. The console shows who/when, generation, reason, and
  the last counts from persistent safety state.
- **Scoped:** Campaigns screen → Kill switch on `scheduled`/`sending`/`active`
  campaigns cancels only that campaign's queued assignments and tokens.
- **Reset:** Audit screen → **Reset global stop** also requires a reason and
  confirmation. It reopens only future scheduling/delivery; previously
  cancelled assignments and revoked links remain terminal. A database reset is
  neither required nor an acceptable normal reset procedure.

---

### 2.8 Send-safety settings

Two controls decide who can be mailed and who has to agree first. Both are
enforced twice — once at the operator API and again in the delivery worker.

| Setting | Default | Effect |
|---|---|---|
| `OPERATOR_APPROVAL_POLICY` | `single-admin` (dev-auth) | `enforce` requires separate security and privacy approval facets from one independent dual-capability operator before a campaign can be scheduled or delivered. The creator cannot self-approve. `single-admin` lets one administrator schedule directly. |
| `KP_ALLOWED_RECIPIENT_DOMAINS` | empty | Comma-separated domains this deployment may mail; subdomains included. Gates CSV import **and** delivery. |
| `KP_WORKER_QUEUED_STALE_HOURS` | `24` | QUEUED assignments older than this on a closed campaign are settled to FAILED. |
| `KP_WORKER_SOURCE_FAILURE_THRESHOLD` | `10` | Consecutive ingestion failures before a source is disabled. |
| `OPERATOR_API_DELIVERY_BATCH_SIZE` | `200` | Recipients per delivery message; also the batch that reuses one SMTP connection. |

Two behaviours worth knowing before you go live:

- **`single-admin` is refused under OIDC.** The operator API will not start with
  it when an identity provider is configured, so the relaxed offline mode cannot
  reach a deployment that mails real people. Azure pins `enforce`.
- **An unset allowlist fails closed under OIDC.** Recipient import is refused
  until it is configured — deliberately, because the alternative is mailing a
  simulation to an unintended domain. On the offline dev stack an unset
  allowlist allows everything and audits each import as unrestricted.

For the intended two-person tenant, assign both `security_approver` and
`privacy_approver` to the independent reviewer, not to the campaign creator.
The platform records both facets separately but permits that one independent
dual-capability reviewer to complete both. It still refuses any creator
self-approval.

### 2.9 Onboarding a sending domain and signing a Rules-of-Engagement

Delivery is gated on two layers that must be satisfied **before** a campaign
can be scheduled: a DNS-verified domain and a signed Rules-of-Engagement.

**1. Onboard a domain (one pass, then zero-config forever).**

```bash
# Candidate lookalike hostnames under a domain you control, each with its
# ready-to-paste DNS records:
GET /api/v1/sending-domains/generate?brand=Okta&base_domain=corp-training.example

# Or onboard an exact domain:
POST /api/v1/sending-domains/challenge
{"domain": "corp-benefits.example", "relay": "ses"}   # ses|mailgun|postfix|smtp
```

Publish the returned records in your DNS zone — the challenge TXT, the SPF
record (it must authorize the relay you configured, or the mail will not
deliver), DMARC, and the DKIM value minted by your relay provider. Then:

```bash
POST /api/v1/sending-domains/verify   {"domain": "corp-benefits.example"}
```

Verification is a live DNS observation and fails closed: no record, a wrong
value, or a resolver error is reported unverified. Once verified, the domain
may be named in an RoE and used as a sending domain (`KP_SENDING_DOMAINS`).
After that one pass, any campaign may send from it with any display name and
local part — the wizard's "zero-config after one pass" property.

**Deliverability truth:** mail only delivers from domains you control with
valid SPF/DKIM/DMARC. A campaign's requested sender mailbox is honored only
when it sits on a registered pool domain; otherwise the envelope falls back to
`KP_WORKER_SMTP_SENDER`, because sending as an unauthenticated domain never
lands. No relay in this platform sends deliverable mail as an unowned domain.

**2. Sign a Rules-of-Engagement** (needs a verified target domain; the API
rejects any domain that has not passed the DNS challenge):

```bash
POST /api/v1/roe
{
  "authorizing_party": "Example Corp",
  "terms": "Q3 training: recipients confined to the verified example.com domain.",
  "window_start": "2026-09-01T00:00:00Z",
  "window_end":   "2026-10-01T00:00:00Z",
  "target_domains": ["example.com"]
}
```

The signature binds `terms_hash | signer | signed_at` under `KP_ROE_SIGNING_KEY`
(shared by API and workers). Scheduling requires an unrevoked RoE whose window
contains the campaign's delivery window and whose target domains cover every
recipient. Delivery re-verifies the signature and the active window per batch,
and any recipient outside the target domains is refused
(`target_domain_not_roe_covered`). Revoke with `POST /api/v1/roe/{id}/revoke` —
its campaigns fail closed immediately.

**Bootstrap note:** `scripts/run_console.sh` and `scripts/install.sh` generate
the RoE/domain-verification keys, apply every current migration, and seed the
local demo. After upgrading an existing clone, rerun one of those launch paths;
do not target an old migration number manually.

### 2.10 Standing up a new Azure tenant

This is not yet an end-to-end GUI workflow. The console has five non-secret
configuration pages and exactly three execution stages—`foundation_bootstrap`,
`foundation_finalize`, and `workloads`—plus a narrow reviewed GitHub Actions dispatcher,
but the initial Azure/Entra/GitHub bootstrap, provider grants, DNS/certificates,
and live qualification remain external actions. The managed Terraform stack also
does not currently configure the server-side GitHub dispatcher credential, so a
fresh deployment is not GUI-complete out of the box.

Integration setup is provider-aware. Operators explicitly choose SMTP or ACS
and Mailpit or Microsoft 365; only the active provider's fields are visible,
required, tested, persisted, or supplied to setup assistance, while inactive
saved values are preserved. Changing provider or destination requires the new
candidate to validate before an atomic credential rebind. ACS testing contacts
only an exact HTTPS `*.communication.azure.com:443` origin and sends no message
or credential, so `reachable_unverified` is a warning rather than success.
Microsoft 365 tests one quoted, bounded Graph delta path; a local bearer requires
strict 2xx, absence of a bearer proves reachability only, and 401/403/redirects
block save. Managed mode does not read local tokens or instantiate operator-side
managed identity.

The approved non-local HTTPS `/propose` and `/setup-assist` gateway remains a
supported optional adapter. It is not the default supported AI architecture;
that target is the pinned internal `llama.cpp` worker role/job described above.
Loopback, embedded credentials, queries, and fragments are rejected for the
gateway adapter. Pattern approval commits a durable generation request
and reports only that request boundary. Queue execution, provider response, and
draft completion remain asynchronous, and live AI-provider qualification is
still open. Local setup guidance may continue to use its explicitly disposable
mock/fallback path; that does not qualify either the internal-model runtime or
the optional gateway adapter.

Privacy export is authenticated `POST`; privacy list/export data is marked
`private, no-store`, and cookie-authenticated mutations require trusted
same-origin CSRF metadata. OIDC discovery/authorization/token/JWKS URLs are
issuer-origin bound, resolved once and IP-pinned for each request with Host/SNI
preserved, and used without environment proxies, HTTP/2, or redirects. A
cross-origin authorization endpoint blocks navigation; cross-origin token or
JWKS endpoints block before code, credential, or token transmission.

The reviewed workflow is frozen to SHA-256
`ca6c0cd44cd889cc8a6e06d0d7a898e70c17ed739f0c54660958475ef2381d69`.
`foundation_bootstrap` plans and applies the complete
`deploy_workloads=false` foundation, including ACR, private-network, data,
ACS/email/domain, and DNS resources, without Terraform targets. It refuses
delete/replacement, explicitly forbids sender/association changes, and
initiates Domain/SPF/DKIM/DKIM2 verification. `foundation_finalize` permits
only those exact changes after fresh verification; `workloads` then revalidates
the exact foundation before immutable deployment. GUI export, API validation,
Terraform, and preflight enforce the same one-label HTTPS
`*.communication.azure.com:443` endpoint. After deployment, the workflow
requires exactly one active Healthy/Provisioned worker revision, every enabled
role ready in two consecutive simultaneous Log Analytics observations, and a
final health check of that same revision before recording environment health.
The tracking application receives bounded trusted-proxy CIDRs derived from the
Container Apps infrastructure subnet plus loopback; it trusts forwarding only
from a trusted direct peer, walks canonical `X-Forwarded-For` hops right-to-left,
and leaves Uvicorn proxy rewriting disabled.
Its live ACS readback, verification initiation, bounded evidence artifact, and
fail-closed connector digest contracts are implemented locally; a mismatch
blocks dispatch.
The connector locally validates protected-environment metadata/reviewers, exact
workflow/ref/content, the new workflow run's identity/status, and owner-bound
Redis environment/operation leases. The recovered Terraform provider tree also
passes provider-backed local initialization and validation. Neither result, nor
the implemented worker/proxy gate, is a live GitHub or Azure qualification.

The historical 2026-08-28 read-only preflight confirmed the selected subscription and
tenant, subscription Owner authority, `eastus2`, and the required registered
providers, including `Microsoft.Communication`. It also found no Terraform
backend, foundation group, platform Entra applications, or application resources,
and the GitHub repository was not deployment-ready. The 2026-08-29 GitHub re-audit
proves valid `ELDSRQ` authentication with `repo`/`workflow` scopes, public and
enabled `ELDSRQ/kingphisher-phoenix` with default `main`, Actions enabled, and
the Azure workflow active, with no billing-disabled run signal. It also proves
zero environments, variables, secrets, rulesets, and workflow runs, unprotected
`main`, disabled secret scanning and push protection, and remote `main` still at
old-tree SHA `1403d944a40214714b6cbfcf5cbabc4fa7225eb9`. Azure management-plane
state was not revalidated because the sandbox could not resolve
`management.azure.com`; do not promote the historical inventory to current
proof. Treat this as prerequisite inventory, not deployment evidence. No workflow dispatch/run
or Azure apply was performed.

Use [Azure deployment](docs/AZURE_DEPLOYMENT.md) for the exact staging boundary.
The complete six-input command printed by `scripts/azure_bootstrap.sh` is a
break-glass contract reference, not a normal deployment or production-readiness
claim. The GUI binds canonical non-secret configuration, an opaque request ID,
and the reviewed revision before dispatch. Use `scripts/azure_preflight.sh` with
the GUI-exported Terraform values, then use the read-only exact-resource
`scripts/azure_mail_check.sh`; actual delivery proof must still run through an
approved one-recipient GUI canary. Simulations use a dedicated customer-managed
ACS domain; Azure-managed `*.azurecomm.net` test domains are rejected.

## 3. Monitoring

- `curl http://127.0.0.1:8000/readyz` and `:8001/readyz` → 200 only when the
  dependency readiness checks pass. `/healthz` remains a liveness/compatibility
  endpoint and is not sufficient release evidence.
- Console `/api/v1/console/status` (authenticated) → per-service + per-worker
  alive flags from pidfiles.
- Worker/API logs: `data/logs/*.log` (per-process). The macOS app writes launcher
  output to `data/logs/launcher.log`; an installer-started launcher writes to
  `/tmp/kingphisher-install.log`.
- Supervised process logs rotate automatically at 10 MB with three backups
  (`.log.1` through `.log.3`), bounding the normal local footprint to about
  40 MB per process. Repeated worker infrastructure failures use exponential
  backoff capped at 30 seconds so an unavailable dependency cannot create a
  high-rate traceback loop.
- Mailpit web UI: `http://127.0.0.1:8025` (password `MAILPIT_API_PASSWORD`;
  admin username is arbitrary under HTTP Basic). SMTP relay `127.0.0.1:1025`.
- OTel collector: `:4317/:4318`.

For the `.140` worker, execute log/readiness commands over SSH in the canonical
source `/Users/edierks/Projects/kingphisher-phoenix`, and remember that all
listed loopback addresses are remote. Project Docker inspection uses
`scripts/operator/remote-docker-worker/external-engine.sh docker ...` or
`... compose ...`; an ambient `docker` command inspects the shared engine and
is not valid project evidence.

---

## 4. Stopping, restarting, upgrading

- GUI: console Settings → **Restart services** touches `data/run/restart`; the
  local supervisor restarts everything.
- Full shutdown is deliberately not exposed through the browser or a remote
  HTTP endpoint because restarting afterward requires out-of-band access. The
  old process-stop capability and marker are absent from the browser, supervisor,
  and launcher. Quit through the OS/launcher or signal the terminal-managed
  launcher, then relaunch with `Kingphisher Launcher.app` or
  `./scripts/run_console.sh`.
- Upgrade a clone: `git pull && ./scripts/install.sh --skip-deps` — migrations
  and both preservation preflights apply automatically. Do not bypass the
  launcher with a direct Compose recovery command when `docker-compose.yml`
  changes; let the gated path verify preserved volume identity and stateful
  images before it reconciles the running services.

---

## 5. Recovery

### 5.1 Preservation-first local recovery

Do not reset schemas, delete volumes, remove images, or rebuild the Python
environment as a troubleshooting shortcut. Before any Compose start, run the
inspection-only preservation gate:

```bash
scripts/operator/deployment-preflight/run.sh --phase prestart
```

It records disk headroom, Docker/Compose state, and exact persistent-volume
identity without changing any resource. An entirely absent project is a clean
first-deployment boundary; an existing project must have the complete expected
volume identities. Partial or mismatched state blocks startup so Compose cannot
silently create a replacement volume. Next, the normal one-click path runs
`scripts/operator/base-image-qualification/run.sh`, which verifies immutable
stateful image references, selected-platform manifests, required account and
entrypoint files, and working service binaries using disposable hardened probes.

After the preserved stack is running and migrations, audit bootstrap, and seed
have completed through the normal launcher, it runs:

```bash
scripts/operator/deployment-preflight/run.sh --phase ready
```

The `ready` phase adds PostgreSQL/Redis health and current-migration-head proof.
Preserve `data/recovery/`, `.env`, the current volume names, and both preflight
reports before attempting a repair. If a restore is necessary, stop and use a
reviewed backup/restore procedure with explicit source, destination, checksum,
restore point, and rollback evidence; this runbook does not authorize
overwriting the working database. Reconcile diagnosed drift in place against
that evidence. Do not turn an uncertain result into automatic cleanup or a new
deployment identity.

### 5.2 External-worker checkpoint, restore, and rollback

The canonical source on `.140` is
`/Users/edierks/Projects/kingphisher-phoenix`; the small
`~/projects/codex-test/phishing-awareness-platform` staging tree is not a valid
runtime source. Before cutover or repair, validate a new logical PostgreSQL and
Redis checkpoint, encrypt it to the reviewed age recipient on
`DockerExternal`, and record its digest. Stop only the project host supervisor
and project containers. Leave every unrelated Docker Desktop workload running.

Restore only into a clean external engine with `restore-state.sh`; existing
project containers or volumes block. Redis RDB loading and non-empty AOF
materialization must complete before its normal AOF-enabled service starts.
Then require all Compose working-directory labels to resolve to the canonical
source, exact migration head, expected database tables, Redis durability,
audit-chain verification, both `/readyz` endpoints, installation verification,
and live local E2E evidence.

Rollback never deletes either copy: stop the external project supervisor and
only its containers, stop Colima without deleting it, select Docker Desktop
explicitly for the preserved internal project copy, and restart that copy.
Never run both stacks simultaneously because their host ports conflict. Never
use Compose `down`, `colima delete`, Lima disk deletion, volume/image/builder
removal, or prune.

### 5.3 Password/secret rotation on an existing stack

`bootstrap_env.sh` preserves existing values. To rotate:
- Postgres/Redis/audit-writer passwords: change the three values in `.env`,
  then reconcile the existing roles in place under a reviewed change. Never
  delete/recreate the data volume to make `initdb` run again. Until the in-place
  credential workflow is automated and recovery-tested, treat password rotation
  as a blocked administrator procedure rather than improvising a destructive
  reset.
- Recipient KEK in disposable local mode: a manually coordinated local keyring
  may place a new unique 1–32 character ID/key in the operator and worker active
  settings while retaining the old `key-id=64-hex` value in both prior-key
  settings. This is not a qualified production procedure and there is no bulk
  re-encryption/retirement tool.
- Recipient KEK in managed Azure: prior-key input is metadata-bound
  legacy/recovery support only. The first foundation establishes the active ID;
  later GUI dispatches must preserve it and active rotation is deliberately
  blocked. The active KEK is Terraform-generated and remains in protected state
  and history. `prevent_destroy` blocks replacement but also complicates
  teardown. Follow [the recovery contract](infrastructure/terraform/CIPHERTEXT_ROTATION.md)
  for direct Key Vault preparation. Never retire a prior key until a separately
  reviewed bulk rewrite/decrypt proof exists; safe pre-stage/prove/promote and
  bulk re-encryption remain future work.
- Audit HMAC/JWT: replace the value with 64 hex chars (256-bit). Rotating the
  audit HMAC invalidates verification of the existing audit chain, and rotating
  the console JWT secret invalidates existing sessions. Use a reviewed data
  migration or, for disposable local data only, pair rotation with §5.1.
- `OPERATOR_API_CONSOLE_JWT_SECRET` must be **64 hex chars** (the app rejects
  shorter values).

---

## 6. Troubleshooting

### 6.1 Docker does not answer

The launch, install, and verification scripts bound Docker calls and fail with
an actionable error; they do not restart or prune Docker. On `.140`, first prove
the exact external volume and run `external-engine.sh preflight`; do not start
or select Docker Desktop and do not use `brew services`. The helper may start
the reviewed profile only after the volume/layout/config/source checks pass.
On a separate standalone macOS host, or on Linux, start that host's reviewed
Docker/Colima/system service and verify access. A responding wrong engine is a
failure, not recovery evidence.

### 6.2 Mailpit shows unhealthy

The healthcheck (`wget` on the API) needs ~10 s under gvisor networking —
`docker-compose.yml` now uses `timeout: 10s` + `start_period: 10s`. If it remains
unhealthy, retain the container and inspect its bounded logs, then confirm the
API answers with an authenticated request. Correct the diagnosed configuration
or Docker health fault in place and relaunch through `scripts/run_console.sh`;
do not replace the container or its project state as a troubleshooting shortcut.

### 6.3 Compose fails with "required variable X is missing a value"

`.env` is missing a key the compose file interpolates (`:?`). All required:
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `AUDIT_WRITER_PASSWORD`,
`MAILPIT_API_PASSWORD`. Re-run `scripts/run_console.sh` (bootstrap fills them)
or copy the values from a known-good `.env`.

### 6.4 `/console/` 404s or assets don't load

`OPERATOR_API_CONSOLE_STATIC_DIR` must be absolute or repo-root-relative
(`apps/operator-ui/src/console`). Check the console loads `app.js` with a
Content-Security-Policy that only allows `'self'` assets — do not inline
scripts/styles.

### 6.5 Audit tests fail with "relation audit_events does not exist"

Audit permissions or the migration head are inconsistent — run the
preservation-first preflight in §5.1, retain its evidence, and repair the exact
role/migration drift without resetting the schema.

### 6.6 Errors are reported as KP-001..KP-010

The fail-closed error taxonomy is enforced in the API (auth, capability,
validation, not-found, conflict, deadlock, rate-limit, upstream, internal,
generic). Look up the code in `kp_operator_api` error handling before changing
behavior.

---

## 7. Security notes (non-negotiables)

- **Never commit `.env`.** It is gitignored; secrets live only on the machine.
- Audit is append-only and hash-chained (`make verify-audit`); do not add
  UPDATE/DELETE paths to `audit_events`.
- RBAC restricts campaign scheduling to authorized campaign operators.
- Safety validation is deterministic and outside any AI model (GEN-004 gate);
  campaign content must pass it at save and before delivery.
- The console JWT lives in `sessionStorage` (never `localStorage`) and expires
  in 8 hours.
- Encryption at rest: versioned, key-ID-bound AES-256-GCM protects recipient
  fields with the active KEK and a bounded prior decrypt-only keyring; random
  URL bearers are never stored, and the database keeps only purpose-scoped HMAC
  verifiers. Managed re-encryption/key retirement remains unqualified.
