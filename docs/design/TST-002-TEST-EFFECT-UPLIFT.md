# TST-002 — Test-effect uplift + RED-batch gate validation

Status: propose-then-stop (committed in worktree `worktree-agent-tst002`, not
merged). Docker/Postgres/Redis never run on the controller Mac, so all
Postgres/Redis *effect* validation in this doc defers to CI (Linux) or a remote
host. Playwright, WCAG, and Azure steps are operator-gated.

---

## A. RED-batch validation at the agent-runnable level

### Alembic single head — CONFIRMED
`alembic -c packages/database/alembic.ini heads` reports exactly:

```
0036_launch_gate_submitted_by (head)
```

The AUT-002 migration was renumbered onto `0035_audit_owner_separation`
(AUD-002/003 took 0035), so the chain is linear with a single head. No multiple
heads.

### Two-distinct-approver worker path — EFFECT-LEVEL coverage CONFIRMED
`apps/workers/src/kp_workers/jobs.py` extracts `_two_person_approval_reason()`
and the delivery re-check (`process_delivery`) requires the covering approvals to
span both facets **and** carry ≥2 distinct approver ids, failing closed
otherwise.

Coverage is real-behavior, not source-regex:
- `apps/workers/tests/test_jobs.py::test_worker_rejects_both_facets_from_one_approver`
  builds two real `CampaignApproval` rows from one approver and asserts
  `_two_person_approval_reason(...) == "insufficient_distinct_approvers"`.
- `...::test_worker_rejects_missing_facet` asserts `"missing_approvals"` for a
  single-facet set and for `[]`.
- DB-level companion: `packages/database/tests/test_approval_separation.py`
  exercises the persisted approval facets against Postgres.

These worker tests are **hermetic** and pass locally (see §E).

### Reminder send-gate — EFFECT-LEVEL coverage CONFIRMED (one residual gap noted)
`apps/workers/src/kp_workers/followup_jobs.py::process_reminder` gates each
outbound reminder on the emergency stop, the signed RoE window, and the recipient
allowlist; `unrestricted = not allowlist and approval_policy is SINGLE_ADMIN`.

Effect coverage in `apps/workers/tests/provider_jobs_test.py` calls the real
`process_reminder(context, ...)` and asserts sends are suppressed, e.g.
`test_reminder_job_skips_recipient_outside_the_allowlist` monkeypatches the
sender to raise if invoked and asserts no send occurs; sibling tests cover
completed/expired/revoked/excluded recipients. PLT-002's ENFORCE default is
asserted by `apps/workers/tests/test_config.py::test_default_approval_policy_is_enforce`
and activated on the delivery path by `test_delivery_roe.py`.

Residual gap (noted, not fixed — outside the fixture allowlist): there is no
dedicated effect test asserting that the **new ENFORCE default** fail-closes the
*reminder* path specifically on an empty allowlist. The provider-job tests pin
the historical `single-admin` + `dev_stack` posture to keep exercising the
offline send, and the ENFORCE fail-close is asserted only on the delivery path.
Recommend adding a reminder-path test that, with `approval_policy=ENFORCE` and an
empty allowlist, asserts `process_reminder` sends nothing.

---

## B. TST-002 fixture uplift — postgres schema now built from real migrations

### Finding
Postgres-marked tests build their schema two different ways:

- **Real migrations (good, already correct):** `test_outbox_postgres.py`,
  `test_grant_matrix_effect.py`, `test_audit_anchor_permissions.py`,
  `test_migrations_fresh_install.py`, `test_migration_00*.py` — each creates an
  isolated database and runs `alembic command.upgrade(config, "head")`.
- **`Base.metadata.create_all()` (the drift risk):**
  `test_approval_separation.py`, `test_campaign_service.py`,
  `test_campaign_audience.py`, `test_audit_store.py`,
  `test_campaign_program_service.py`. These rebuild the schema from ORM metadata,
  so they never exercise what *only migrations* apply: audit-table ownership
  transfer to the NOLOGIN `audit_owner` (0035), grant matrices, triggers, and
  function-based indexes.

Why `create_all()` is not equivalent to the migrated schema: the guard
`test_migration_autogenerate_drift.py` deliberately ignores `remove_*` diffs, so
it proves migrations ⊇ ORM *shape* but says nothing about ownership/grants/
triggers — exactly the surface `create_all()` skips. `test_audit_store.py` even
hand-reproduces migration behavior (it manually `CREATE TABLE ... audit_chain_head`
and `GRANT ... TO audit_writer`), which is direct evidence of the drift.

### Change made (fixture plumbing only)
New helper `packages/database/tests/_migrate_schema.py` exposes
`rebuild_public_schema_via_migrations(url)`: it `DROP SCHEMA public CASCADE` /
`CREATE SCHEMA public`, then runs `alembic upgrade head` against `url` (setting
both `DATABASE_URL` and the config's `sqlalchemy.url` so `env.py` targets the
right database). Notes:
- `DROP SCHEMA public CASCADE` needs no more privilege than the `drop_all()` it
  replaces (both require ownership of the dropped objects), so it does not raise
  the bar for the existing `kingphisher_test` role.
- The role-creating migrations (e.g. 0035 `audit_owner`) guard with
  `IF NOT EXISTS`, so repeating the rebuild between tests against the shared
  disposable database is safe; dropping the schema also removes
  `alembic_version`, so the chain always runs base→head.
- It is a **sibling module**, not a second `conftest.py`, to avoid the
  `conftest` basename collision with `apps/operator-api/tests` under pytest's
  default prepend import mode. It is imported only from `postgres`-marked tests.

Converted to use it (drop_all/create_all → migrate-to-head):
- `test_approval_separation.py` — the AUT-002 two-person-approval DB effect test.
- `test_campaign_service.py`
- `test_campaign_audience.py` (RoE seeding preserved after the rebuild)

### Deliberately NOT converted (documented, needs more than fixture plumbing)
- **`test_audit_store.py`** — writes as the `audit_writer` role and manually
  creates `audit_chain_head` + broad grants on top of `create_all()`. Under the
  migrated schema the audit tables are owned by NOLOGIN `audit_owner` and
  `audit_writer` loses DELETE (0035). Converting is high value (it would finally
  exercise the real audit posture) but it is a **security-relevant behavior
  change** I cannot validate without Postgres, and the manual grant would need to
  be removed (keeping it would *weaken* the posture the test should assert).
  Recommend: route through `rebuild_public_schema_via_migrations`, delete the
  manual `audit_chain_head` CREATE and the `GRANT ... TO audit_writer`, and let
  CI confirm the audit-writer path still round-trips under the migrated grants.
- **`test_campaign_program_service.py`** — uses per-test `search_path` schema
  isolation (`campaign_program_<uuid>`) rather than the shared public schema.
  Alembic migrations hardcode `public.` (e.g. 0035 `ALTER TABLE public.%I ...`),
  so `upgrade head` will not populate a custom schema. Converting it faithfully
  means adopting the **isolated-database** pattern (create a fresh DB, upgrade,
  drop) that `test_outbox_postgres.py` already uses, replacing the search_path
  trick — a structural change beyond mechanical fixture plumbing. Recommend
  scheduling it as a follow-up that mirrors `_isolated_migrated_database`.

---

## C. Playwright console smoke — PROMOTED to a standing gate (`make test-e2e-console`)

> **Update 2026-09-07:** no longer a scaffold. First real-browser run against the live
> .105 console found two defects that could only surface in a browser — it navigated to
> `/` (the SPA is mounted at `/console/`, root 404s) and probed for the login form with a
> non-waiting `count()` that raced the client-side render. Both fixed (711c09d, 433154b);
> the suite is green (2 passed) and is now wired in as `make test-e2e-console` with an
> npm script + pinned `@playwright/test` devDependency. It stays out of `make test`/CI
> because it needs a browser and a live authenticated console.

`apps/operator-ui/tests/e2e/` (new):
- `playwright.config.mjs` — minimal, **no `webServer`** (operator owns stack
  lifecycle), `baseURL` from `OPERATOR_CONSOLE_URL`.
- `console-nav.smoke.spec.mjs` — replaces the *inference* in
  `test_gui_wiring_ui_contract.py::test_every_visible_navigation_item_has_a_view_and_hidden_readiness_links_are_not_rendered`
  with a **real-DOM effect** assertion: the authenticated console renders a
  sidebar button per visible NAV item (no stray buttons; core destinations
  present) and activating one mounts that view (`#console-view` relabels, hash
  follows). DOM anchors verified against `app.js`
  (`nav[aria-label="Operator sections"]`, `#console-view` aria-label
  `"<Label> view"`, `#console-password` login).
- `README.md` — operator run steps.

Not run here: no browsers installed, Playwright not executed, nothing wired into
CI or `make`. The source contract's *negative* assertions (hidden readiness links
absent) are intentionally left in place until effect coverage is broadened.

---

## D. Source-change recommendations I could not make under the allowlist
1. Convert `test_audit_store.py` to the migrated schema and drop its manual
   `audit_chain_head` + `audit_writer` grant (see §B). Highest security signal.
2. Convert `test_campaign_program_service.py` to the isolated-migrated-database
   pattern (see §B).
3. Add a reminder-path ENFORCE fail-close effect test (see §A residual gap).
4. Once §B lands, consider a shared isolated-migrated-database pytest fixture in
   a `packages/database/tests/conftest.py` so all Postgres tests obtain a
   migrated engine uniformly (would also let the per-test files stop hand-rolling
   engine/session wiring).

---

## E. Exact commands to validate effect

Hermetic (agent-runnable; run and GREEN in this worktree):
```
# from the worktree root, after: uv sync --frozen --all-packages
env -i PATH="$PATH" HOME="$HOME" KP_DISABLE_DOTENV=1 KP_TEST_PROFILE=hermetic \
  DATABASE_URL="postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic" \
  AUDIT_DATABASE_URL="postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic" \
  KP_WORKER_DATABASE_URL="postgresql+psycopg://hermetic:hermetic@127.0.0.1:1/kp_hermetic" \
  KP_WORKER_AUDIT_DATABASE_URL="postgresql+psycopg://hermetic_audit:hermetic@127.0.0.1:1/kp_hermetic" \
  REDIS_URL="redis://127.0.0.1:1/14" KP_WORKER_REDIS_URL="redis://127.0.0.1:1/14" \
  uv run --frozen --no-sync python -m pytest \
    apps/workers/tests/test_jobs.py apps/workers/tests/provider_jobs_test.py \
    apps/workers/tests/test_config.py -q -m "not postgres and not redis"

# full hermetic gate (rejects skips):
bash scripts/run-hermetic-tests.sh all
```

Postgres effect (DEFERS to CI / a Docker host — never on the controller Mac):
```
export DATABASE_URL_TEST=postgresql+psycopg://kingphisher:kingphisher@<host>:5432/kingphisher_test
export AUDIT_DATABASE_URL_TEST=postgresql+psycopg://audit_writer:audit_writer@<host>:5432/kingphisher_test
export REDIS_URL_POSTGRES_TEST=redis://<host>:6379/14
make db-init            # alembic upgrade head on the disposable DB
make test-postgres      # runs `-m postgres`; the converted fixtures now build via migrations
```
`make test-postgres` is where the converted `test_approval_separation` /
`test_campaign_service` / `test_campaign_audience` prove they build the migrated
schema. `alembic heads` (single head) is agent-checkable and confirmed above.

Playwright smoke (OPERATOR-RUN only): see
`apps/operator-ui/tests/e2e/README.md`.
