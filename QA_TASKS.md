# QA Findings — Operator Console Human-Operation Pass (2026-08-04)

Scope: fresh install path exercised against the live stack (DB reset to 0005 + seed,
all 8 processes under supervisor, browser console flows driven over HTTP as the GUI
does). Full gate green before and after remediation (111 tests, ruff, mypy).

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

## Environment Workaround (the recurring "pause") — WEDGED DOCKER CLI

Symptom: `docker ps`/`docker context ls` hang forever while Docker Desktop
backend + VM are alive (engine answers `/_ping` OK). Root cause here: the default
CLI proxy socket `~/.docker/run/docker.sock` (held by `com.docker.backend`) accepts
connections but never answers after a Desktop restart; the engine socket
`~/Library/Containers/com.docker.docker/Data/docker.raw.sock` is fine.
Secondary: even with the correct socket, `docker compose up -d` completes the work
(recreate) but the client lingers and never exits (Desktop 4.78.0).

Workaround (in `scripts/bootstrap_env.sh`, wired into `run_console.sh`,
`install.sh`, `verify_install.sh`):
- `bootstrap_docker_host`: probes engine sockets directly with bounded `curl` and
  exports `DOCKER_HOST` — no docker CLI call, cannot hang.
- `bounded <secs> <cmd>`: runs a command under a hard wall-clock bound (macOS has
  no `timeout(1)`); used around `docker compose up -d` so launchers never stall;
  callers then re-verify real state with `docker compose ps`.
Verified: `docker ps` lists 21 containers; `docker compose ps postgres redis
mailpit` returns healthy; `run_console.sh` path exercises both helpers.

## Environment Notes (not app bugs)

- `.env` was rebuilt for QA (`.env.bak-qa` holds the old one): missing
  compose-required keys (POSTGRES_PASSWORD etc.) and a 62-char
  `OPERATOR_API_CONSOLE_JWT_SECRET` (below the 64 required by
  `require_console_jwt_secret`) were repaired; `MAILPIT_API_PASSWORD` must be
  non-empty for compose interpolation.
- `OPERATOR_API_CONSOLE_STATIC_DIR` must be absolute or root-relative.
- Test-DB resets must re-grant schema privileges to `audit_writer`.
- Stack currently running with demo seed restored (campaign + 5 tracking tokens).
