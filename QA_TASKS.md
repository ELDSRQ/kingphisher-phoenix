# QA Findings — Operator Console Human-Operation Pass (2026-08-04)

## Current Wave 38 paused QA overlay (2026-08-29)

This file preserves the historical human-operation findings below; it does not
replace the authoritative goal-aligned policy and evidence matrix in
`docs/WAVE-BUILD-PLAN.md` and `docs/PRODUCTION-READINESS-TASK-MATRIX.md`.
The current product target is one 125-person tenant operated by two IT staff.
Deferred features remain retained and supported but are not expanded; never
delete potentially valuable functionality merely because it is deferred.

Current local/static status:

- **Complete locally:** `ORG-001`. The creator cannot self-approve; one
  independent operator with both approval capabilities may complete the
  separately recorded security and privacy facets. RoE, frozen audience,
  reviewed canary, provider evidence, immutable review, recipient controls,
  emergency stop, and worker rechecks remain mandatory.
- **Complete locally:** `THR-001A` and `DOCSIM-001`. Evidence fidelity is
  preserved through reviewed generation context, and ICS behavior is
  recipient-bound instead of claiming a nonexistent tracked link. The focused
  closure passed 150 tests.
- **Complete locally:** `IMP-001` and `THR-001B`. Guided CSV import includes
  explicit/arbitrary headers, bounded preview, digest-bound apply, safe merge
  and soft-deactivation, and serialized writes. Threats have a bounded GUI
  workbench, daily governed ingestion, default quarantine, explicit activation,
  deterministic draft-pattern creation, and source/provenance rechecks.
- **Retention integration complete locally; consumers open:** `OUT-001`,
  `RET-005`, and `INT-001` at Alembic head
  `0032_source_explicit_curation`. Confirmed interaction is distinct from
  observed events; raw evidence is capped at 365 days; terminal-only projection
  and all current outcome writers share a lock boundary; the PII-free ledger,
  pseudonym configuration, grants, and migrated policy bounds are wired.
  Privacy/RBAC, named-history API, reporting/graph, and export remain open.
- **Independent review:** no P0. One P1 remains: mirror migration `0032`'s
  retention-policy check/single-default index in ORM metadata and test it.
- **Pause gate:** Node syntax, targeted Ruff/format, `git diff --check`, and the
  focused API/tracking/worker/database suite passed with eight PostgreSQL-profile
  skips. Full hermetic, mypy, PostgreSQL/Redis/E2E, image, browser, and cloud
  gates were not rerun after the final edits. That is historical: as of
  2026-08-31 the tree is committed and pushed at `40c611d` and those gates have
  been rerun head-exact — hermetic 2707/103, strict mypy 140 files, external
  PostgreSQL 92, Redis 2, fresh-migration 1, E2E 8/8, and exact-final native
  ARM64 at source `2adb2a2`. Browser/WCAG, native AMD64/registry and
  cloud/provider gates remain open.

The AI QA target is internal-model-first: compare two or three small
permissively licensed models on a fixed sanitized set, then pin the selected
`llama.cpp` runtime/weights in the existing worker role/job. Qualify CPU first;
permit scale-to-zero serverless GPU only when measured, and treat Foundry
serverless/token inference as optional. Foundry managed compute and always-on
GPU are out of scope. `.140` is development/qualification infrastructure only.

Release remains **NO-GO for production and RSA Conference use**. Current-head
`0032` external PostgreSQL/Redis/E2E, exact-final images, native AMD64/registry,
browser/WCAG, Azure/Entra/Graph/ACS/Outlook/DNS/inbox, recovery/rotation, audit
witness, and human-acceptance evidence remain open.

Scope: fresh install path exercised against the live stack (DB reset to 0005 + seed,
all 8 processes under supervisor, browser console flows driven over HTTP as the GUI
does). Full gate green before and after remediation (111 tests, ruff, mypy).

> **Archived point-in-time record.** This file captures the 2026-08-04 host and
> must not be used as current Docker or release guidance. The target worker is
> `192.168.1.140`; canonical source
> `/Users/edierks/Projects/kingphisher-phoenix` will mount read-only in the
> project-only `kingphisher` Colima engine rooted under
> `/Volumes/DockerExternal/KingPhisher-Phoenix`. External preflight/restore
> passed; the internal seven project containers are stopped/preserved. Project commands select the
> external socket explicitly while the remote global context remains
> `desktop-linux`. The shared Docker Desktop engine/unrelated workloads are
> out of scope, and external-mount drift never falls back to it. See
> `scripts/operator/remote-docker-worker/README.md`.
> The legacy encrypted snapshot is unrecoverable because its identity is absent
> and is not the `EXT-002` source; validated snapshot
> `20260829T013332Z-tsX1WQ` passed staging/restore. This archived QA result is
> not production evidence.
> Controller context `kp-external-mac` reports
> `colima-kingphisher|aarch64|/var/lib/docker`; its exact endpoint is
> `ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`,
> and the default remains
> `desktop-linux`.
> The legacy Docker contexts `DockerExternal` and `kp-remote-mac` omit that
> reviewed socket and must never be used for project operations. The similarly
> named `DockerExternal` volume is the required storage target, not a context.
> Rosetta and binfmt remain disabled and are not required for native ARM64.
> The validated snapshot archive SHA-256 is
> `e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`;
> external restore, installation, and `verify_install.sh` passed. The latest
> completed external local profiles also passed at head `0029`; subsequent
> source edits still require the final integrated/image rerun, and
> browser/cloud gates remain NO-GO. PostgreSQL integration jobs use Redis DB14
> and flush only DB14 before/after; the Redis queue contract uses DB15; neither
> test cleanup may touch application DB0.

## Verified Working (PASS)

- Console login: `POST /api/v1/console/session` with on-disk `KP_CONSOLE_PASSWORD` issues JWT; unauthenticated requests 401.
- Console page `/console/` serves with CSP + `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`; logo 200.
- `/api/v1/console/status`: operator-api + tracking-api + all 6 workers reported alive.
- `/api/v1/console/config`: secrets masked correctly; settings save `{"ok": true}`.
- Campaigns/recipients/templates/patterns + approve; CSV import with per-row errors.
- Privacy: notice + DSR lifecycle (submit -> verify -> export -> fulfill).
- Audit chain: `POST /api/v1/audit/verify` -> `{"ok": true, "problems": []}`.
- Kill switch: global + scoped engage work (`cancelled`/`tokens_revoked` returned).

## Bugs Found

### BUG-1 (medium) — Sources screen: 2 of 3 dropdown options always 422 — FIXED
`apps/operator-ui/src/console/app.js` offered `["rss", "feed", "api"]`; API enum
(`SourceType`) is `advisory | rss | stix | bulk_download | curated`.
Fix: dropdown now lists the five valid enum values. All five create 201 (verified).

### BUG-2 (low/UX) — Kill-switch state not readable; button always armed — FIXED
Added `GET /api/v1/kill-switch` (routers.py) that reads the latest global
`kill-switch.engage` audit event -> `{engaged, engaged_at, actor, last_cancelled,
last_tokens_revoked}` (the switch is one-shot by design; engagement is
immutable once recorded). Console Audit view now fetches it: button becomes
"Kill switch engaged", disabled, and a status line shows who/when/what.
Verified: engaged=false -> engage (5 revoked) -> engaged=true with details.

### BUG-3 (medium) — Privacy requests list: Verify/Fulfill buttons dead — FIXED
List entries use `privacy_request_id`; console called `/privacy/requests/${r.request_id}/...`
-> `/undefined/...` -> 404. Fixed both buttons to `r.privacy_request_id`, and added
an Export action for `in_progress` `access_export` requests (calls the GET export
endpoint and reports record count/mailboxes).
Verified end-to-end: submit -> verify -> export -> fulfill all 200/201.

### BUG-4 (HIGH, pre-existing) — app.js never parsed in a browser — FIXED
`node --check` fails on HEAD: the settings view had `])),` (extra `)`) at the
"Save changes" card. A JS parse error blanks the whole console SPA — the GUI was
not functional in a browser until this was fixed. Remediated and verified with
`node --check`; served JS confirmed to contain the fixes.
(Note: the gate has no JS lint; consider `node --check apps/operator-ui/src/console/app.js`
in `make lint`.)

### BUG-5 (low, pre-existing) — mailpit healthcheck always times out — FIXED
Healthcheck `wget ... /api/v1/info` with `timeout: 3s` was killed with "Health
check exceeded timeout (3s)" on this machine (gvisor networking is slow), leaving
mailpit permanently `unhealthy` and failing `verify_install.sh`'s mailpit check.
Fix: `interval/timeout: 10s` + `start_period: 10s` in docker-compose.yml.
Verified: mailpit now reports `healthy`; API/SMTP 200.

## Archived environment fix — wedged Docker CLI (resolved on 2026-08-04)

**Root cause (verified 2026-08-04):** The default CLI proxy socket
`~/.docker/run/docker.sock` was wedged — `com.docker.backend` held ~10
accumulated open connections (leaked from hung `docker` invocations) and the
proxy stopped servicing new connections. The engine itself
(`docker.raw.sock`) was healthy.

**Point-in-time fix:** A dedicated Docker context `kp-engine` pointed at that
host's live engine socket and was made default. This is superseded architecture,
not permission to change the current controller or `.140` global context.

The repo launchers still include the `bootstrap_docker_host` + `bounded`
helpers as a safety net — they auto-skip when the default context works.

## Environment Notes (not app bugs)

- `.env` was rebuilt for QA (`.env.bak-qa` holds the old one): missing
  compose-required keys (POSTGRES_PASSWORD etc.) and a 62-char
  `OPERATOR_API_CONSOLE_JWT_SECRET` (below the 64 required by
  `require_console_jwt_secret`) were repaired; `MAILPIT_API_PASSWORD` must be
  non-empty for compose interpolation.
- `OPERATOR_API_CONSOLE_STATIC_DIR` must be absolute or root-relative.
- Test-DB resets must re-grant schema privileges to `audit_writer`.
- At that snapshot, the stack was running with the demo seed restored (campaign
  + 5 tracking tokens).
