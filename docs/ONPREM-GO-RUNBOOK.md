# On-prem GO runbook (readiness gates D1–D6)

Purpose: the exact steps to clear the remaining `AGENTS.md` NO-GO gates for the
on-prem (.105 / standalone) deployment, and — once on-prem is signed off — to
bring Azure up and land the same remediations there. Production/RSA use stays
**NO-GO** until every gate below is proven and a human signs D6.

Status as of 2026-09-27 (this session): all QA-report code remediations are
landed on `main` and deployed to .105. Gate evidence collected this session:

| Gate | What it proves | Status |
| --- | --- | --- |
| D1 hermetic suite | ~3.4k no-skip unit/contract tests | ✅ `3424 passed` (local, 2026-09-27) |
| D1 postgres/redis | integration on a disposable migrated DB | ✅ green on every PR CI (self-hosted .105 runner) |
| D1 live lifecycle | a real campaign end-to-end | ✅ Mailpit send/track/train/report canary passed (.105, 2026-09-27) |
| D2 release images | every release image builds + runs from a clean context | ✅ **passed** (.105, 2026-09-27) — all images qualified linux/amd64; evidence `data/qualification/release-images/20260927T235417Z-952358-21110/` |
| D3 accessibility | axe-core WCAG 2.1 AA, no blocking violations | ✅ `5 passed` live console (2026-09-27) |
| D3 manual WCAG | keyboard order + screen-reader pass (axe finds ~half) | ⏳ human |
| D5 recovery | backup/restore drill of app data | ✅ backup→restore to disposable DB in 3 s, schema `0040`, data intact, dropped clean (.105, 2026-09-27) |
| D6 human acceptance | a non-builder drives a full campaign unassisted | ⏳ human — `docs/D6-HUMAN-ACCEPTANCE-SCRIPT.md` |

Two live-console *contract* caveats surfaced during the D1 run (neither is a
product defect): the azure-wizard e2e sent three `tf_state_*` keys the schema
dropped — fixed (the endpoint correctly fail-closes on unknown keys); and the
onboarding `identity` connector self-test fails on the `.105` dev-auth stack
because no reachable OIDC issuer is wired there (graph/ai/smtp pass) — an
expected dev-stack artifact left for a decision (wire mock-idp as the issuer,
or skip `identity` under dev auth), not force-passed.

All commands run from the WSL2 working copy on .105 unless noted:
`ssh -p 2222 builder@192.168.1.105` then `cd ~/phishing-awareness-platform`.
Console-facing gates run from the Mac over the tunnel:
`ssh -N -L 18000:127.0.0.1:8000 -L 18001:127.0.0.1:8001 erikd@192.168.1.105`.

---

## D1 — full suite

Hermetic (no infra) — already green this session; re-run anytime:
```
make test
```
PostgreSQL + Redis integration (proven on every PR in CI; to run by hand on
.105 against the disposable test DB, never the app DB):
```
export DATABASE_URL_TEST=postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test
export AUDIT_DATABASE_URL_TEST=postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher_test
export REDIS_URL_POSTGRES_TEST=redis://localhost:6379/14
make test-postgres
make test-redis
```
Live campaign lifecycle (sends through the local Mailpit; opt-in, single
operator can drive it — currently 8/8):
```
export KP_E2E_PASSWORD=<local-stack KP_CONSOLE_PASSWORD>
export KP_E2E_LIFECYCLE=1
make test-e2e
```

## D2 — release images
Builds and executes every release + mock image from an isolated source context.
Heavy; .105 is shared, so run it when the host is quiet:
```
make verify-images        # = scripts/operator/release/verify_images.sh
```

## D3 — accessibility
Automated (green this session) — re-run from the Mac with the tunnel up:
```
export OPERATOR_CONSOLE_URL=http://localhost:18000
export OPERATOR_CONSOLE_PASSWORD=<local-stack KP_CONSOLE_PASSWORD>
make test-a11y-console
```
Then the **manual** WCAG pass (axe catches ~half): tab through each view with no
mouse, confirm focus order and visible focus, and run one screen-reader pass on
the login + campaign-create + approvals flows. Record findings; this is a human
gate.

## D5 — recovery drill
The DR mechanism mirrors every non-GitHub secret + state to Alice (.36) and is
owned by a separate workstream — do not modify it here. To *exercise* recovery
for on-prem sign-off: (1) confirm the DR sync is current
(`docs/DR-AUTO-SYNC-TEMPLATE.md`); (2) take a fresh Postgres dump of the app DB
and the `data/` + `data/recovery/` trees; (3) restore into a throwaway stack and
run `make verify-install` against it. Record the restore time and that audit
state verified. Never restore over the live volumes.

## D6 — human acceptance (final gate, human-only)
Follow `docs/D6-HUMAN-ACCEPTANCE-SCRIPT.md` verbatim. The driver must **not** be
the builder, nothing is fixed mid-run, and hesitations are findings. Warm the
generation model first (poll the endpoint; do not use a fixed wait). A pass here
is what flips on-prem from code-complete to human-ready.

---

## Azure — bring up + land the remediations (GATED)

Do this only after on-prem D6 is signed. It is **billable** and needs an
interactive `az login` (identity/1h-expiry caveats in
`docs/STANDALONE-READINESS.md`). It reverses `azure-nightly-shutdown.sh`.

1. Authenticate (operator, in a `!` shell — Claude cannot run `az login`):
   ```
   AZURE_CONFIG_DIR=$HOME/.azure az login
   ```
2. Start the self-hosted CI runner (private deploys queue forever without it):
   ```
   AZURE_CONFIG_DIR=$HOME/.azure az vm start -g rg-kp-staging -n vm-kp-staging-runner
   ```
3. Start the database:
   ```
   az postgres flexible-server start -g rg-kp-staging -n <psql-kp-staging-*>
   ```
4. Restore Container App replicas the idle set to 0 (operator, tracking, worker,
   ai-gateway) — the DB start does **not** do this:
   ```
   for app in <operator> <tracking> <worker> <ai-gateway>; do \
     az containerapp update -g rg-kp-staging -n "$app" --min-replicas 1; done
   ```
5. Deploy `main` (carrying every remediation incl. migration `0040`) via the
   private workflow on the now-running runner:
   ```
   gh workflow run azure-deploy.yml --ref main
   gh run watch $(gh run list --workflow azure-deploy.yml -L1 --json databaseId -q '.[0].databaseId')
   ```
   The deploy runs `alembic upgrade head` in the operator container, so `0040`
   lands on the Azure DB the same way it did on .105.
6. Cloud/provider gate: `KP_RUN_AZURE_LIVE=1 make test-live-azure`, then confirm
   ACS delivered receipts for a canary (H9's spread and H8/H10 alerts exercise
   the same delivery + alert paths as on-prem).
7. Re-idle when finished to stop the spend:
   ```
   bash scripts/operator/azure-nightly-shutdown.sh
   ```

H1 (Azure console surface reduction) is the one Azure-specific QA finding still
open; it is a console-only change deferred with Azure and can land in the same
window.
