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

## Environment Fix — WEDGED DOCKER CLI (RESOLVED)

**Root cause (verified 2026-08-04):** The default CLI proxy socket
`~/.docker/run/docker.sock` was wedged — `com.docker.backend` held ~10
accumulated open connections (leaked from hung `docker` invocations) and the
proxy stopped servicing new connections. The engine itself
(`docker.raw.sock`) was healthy.

**Permanent fix:** Created a dedicated docker context `kp-engine` pointing at the
live engine socket and made it the default (`docker context use kp-engine`). All
`docker` / `docker compose` commands now work instantly with no hang, no env
vars needed, persisting across shell restarts.

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
- Stack currently running with demo seed restored (campaign + 5 tracking tokens).
