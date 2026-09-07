# Next-session resume prompt (copy/paste)

> Copy everything in the fenced block below into a fresh session to resume seamlessly.
> Written 2026-09-05, updated 2026-09-06. Repo head at handoff: `e47570f` (fully pushed to origin/main).

```
You are resuming the Kingphisher-Phoenix phishing-awareness-platform build. Repo:
/Users/edierks/projects/codex-test/phishing-awareness-platform (branch main, head e47570f,
fully pushed to origin/main — the app is recovery-safe: code on GitHub, .env in the DR archive).

## 2026-09-06 — FOUR-PERSPECTIVE REVIEW-FINDINGS WAVE LANDED (read before the local bring-up)
A full architect/senior-dev/security/portability review (docs/design/REVIEW-FINDINGS-2026-09.md)
was turned into 11 tracked tasks and ALL 11 landed this session, plus follow-ups. Status +
per-task commits + the deferred-follow-up list live in docs/WAVE-BUILD-PLAN.md (section
"Follow-ups from the 2026-09 wave build"). What changed that AFFECTS HOW YOU OPERATE:

- **PLT-002 — the default approval posture is now ENFORCE, not SINGLE_ADMIN.** SINGLE_ADMIN
  (two-person approval relaxed) AND the empty-allowlist allow-all now require an explicit
  `KP_DEV_STACK=1` marker together with development runtime; without it, startup REFUSES the
  relaxations and delivery/reminders fail CLOSED on an empty allowlist. `.env.example` ships
  `KP_DEV_STACK=1`, so a fresh local demo keeps the single-admin + solo-canary path. **If the
  .105 local stack refuses to start, or the solo CANARY send is blocked, confirm the local
  .env has `KP_DEV_STACK=1` and (worker) runtime_mode=development / (operator) oidc_mode=dev.**
  Managed (`config_store=managed`) now REQUIRES oidc_mode=oidc (managed+dev is refused).
- **AUT-002 — two-person approval now requires two DISTINCT people.** Self-approval and one
  dual-capability admin approving both facets are rejected, at the API AND re-checked in the
  delivery worker (canary included). Migration head is now `0036_launch_gate_submitted_by`.
- **AUD-002/AUD-003 — audit hardening.** One grant matrix (drift-gated); audit_writer is no
  longer OWNER of the audit tables on local installs; audit anchors are read-back/chain-verified
  with a local WORM provider; a stale/mismatched anchor disables privileged mutations (fail-open
  on absence so it never bricks a fresh local stack).
- **AI-016 — ai-gateway hardened.** Bearer required + fail-CLOSED `require_auth` (managed
  terraform now wires a shared secret across gateway + generation worker). LOCAL/dev is auth-OFF
  by default — no change to the .105 bring-up.
- **UX-011 console usability** (masked recipient names, "needs my decision" approver queue,
  emergency-stop in the sidebar, clone→re-sign-RoE, report.csv + evidence.zip export, a SAFE
  server-computed HTML structure summary in the template preview). SAFETY NOTE: the operator
  console NEVER renders/executes template HTML (no srcdoc/innerHTML) — do not reintroduce that.
- **CNT-002** Jinja sandbox enforced; **OPS-002** CI on PR+push:main; **TST-002** postgres
  test fixtures now build from real migrations; **ARC-002 Ph1** the Azure deploy connector is
  flag-gated (deploy_connector_enabled, default on).

STILL OPEN (deferred, reasons in WAVE-BUILD-PLAN.md): the two Docker-only postgres fixture
conversions (test_audit_store, test_campaign_program_service), UX-011 §2b proof send-to-self,
UX-011 send-time spread (needs a migration + worker), and ARC-002 Items 2/3 (god-module split;
Postgres-only-queue evaluation). None block the real-send goal below.

GATE STATUS — READ THIS, IT IS NOT ALL GREEN:
- `make test` (hermetic) = 2882 passed. Its only 12 failures are the retired macOS-only .140
  remote-checkpoint contract tests, which DESELECT on the Linux CI (they run on the Mac because
  macos_only isn't filtered there). Not a regression — expected.
- **GitHub Actions CI (`.github/workflows/ci.yml`, added by OPS-002) has NEVER passed.** OPS-002
  turned on the postgres/redis integration gates that were previously manual-only, and they fail:
  ~15 failures in packages/database (test_audit_store, test_campaign_service, test_grant_matrix_effect,
  test_outbox_postgres, test_migration_autogenerate_drift) + apps/operator-api test_sending_wizard.
  Partly pre-existing conditions the new gate exposed for the first time, and partly a bug the
  TST-002 fixture conversion introduced: `rebuild_public_schema_via_migrations` dropped schema
  `public` without restoring `GRANT USAGE ON SCHEMA public TO PUBLIC`, so every non-owner role
  (audit_writer, kp_operator, …) silently lost schema access for the rest of the run — which
  cascades order-dependently across the whole postgres profile. A fix exists on branch
  `worktree-agent-def1-pgfixtures` and needs validating against a real Postgres.
- **Do NOT enable branch protection until CI is green** — it would block all merges.
- You CAN run the postgres gate: the .105 stack has postgres on 127.0.0.1:5432 with the disposable
  `kingphisher_test` DB and redis on 6379. Never point DATABASE_URL_TEST at `kingphisher` (the app
  DB) — the fixtures DROP SCHEMA.

## SCOPE (READ FIRST — hard rule)
Work ONLY inside this repo (phishing-awareness-platform). NEVER modify any other project.
A SEPARATE agent owns CROW (~/crow) and the DR/backup mechanism (dr-sync, the Alice/.36
archive, the crow-* launchd agents) — do NOT edit ~/crow, ~/bin, or ~/Library/LaunchAgents,
even though the harness may list them as writable working dirs. Reading them for context is
fine; changing them is not. Any process/CPU guardrail must WARN, never auto-kill (the operator
runs several concurrent agent/coding sessions and a false kill mid-build is unacceptable).

## COST — AZURE IDLED; THE FULL APP + QWEN NOW RUN LOCAL ON .105 (2026-09-05)
Azure spend was ~$800/mo, so the expensive tier is IDLED (reversible via az): all 4 Container
Apps at min-replicas 0, Postgres STOPPED (retains data; auto-starts in ~7 days), CI runner VM
deallocated. Only the cheap real-send slice (ACS + email domain + DNS + Event Grid + Entra)
stays up. The Azure console is therefore OFFLINE until you resume — expected, not broken.

THE FULL APP IS ALREADY RUNNING LOCALLY on the .105 WSL Docker host (repo
/root/kingphisher-phoenix): scripts/supervisor.py with operator-api :8000 (/readyz 200),
tracking-api :8001 (/readyz 200), and all 8 workers (ingestion/generation/delivery/retention/
mailbox/reminder/alert/directory); infra + mocks (postgres/redis/mailpit/otel/mock-idp/
mock-graph/mock-ai) up; audit root bootstrapped; demo seeded. Dev auth mode
(OPERATOR_API_OIDC_MODE=dev) — no Entra needed locally.
REACH THE LOCAL CONSOLE FROM THE MAC:
  ssh -N -o ControlMaster=no -o ControlPath=none -L 8000:127.0.0.1:8000 -L 8001:127.0.0.1:8001 erikd@192.168.1.105
then open http://localhost:8000/console.

QWEN IS LOCAL AND PROVEN: llama.cpp kp-llama on :18081 serves the AI-010-validated GGUF
(sha256 matches the ai-llama Dockerfile pins), ~12 tok/s with --threads 8; ai-gateway on :8090;
worker-generation wired via KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090. App->Qwen /propose
generation is VERIFIED (schema-valid, simulation-framed). Qwen does NOT need Azure
(deploy_ai_gateway=false).

BUILD + TEST RUN FULLY LOCAL WITH ZERO AZURE (subagent-verified). Do NOT restart Azure to work
— bring the full app up on .105 via `make bootstrap` -> `scripts/run_console.sh`; tests via
`make test` / `test-postgres` / `test-redis` / `test-e2e`. Full plan + per-dependency local
mapping + the local-Qwen bring-up runbook: docs/LOCAL-FIRST-MIGRATION-PLAN.md. Cost tiers +
toggles (deploy_data_plane, environments/idle.tfvars) + the azure-idle.sh stop/start runbook:
docs/HYBRID-AZURE-LOCAL-PLAN.md. Resume Azure ONLY for a real send:
`scripts/operator/azure-idle.sh start`; re-idle after with `... stop`.

IDENTITY OPTION (IAM-003, new): operator login can drop Entra/O365 via a config-only OIDC
issuer swap to a self-hosted Keycloak (local user DB) — docs/design/INTERNAL-IDP-KEYCLOAK.md +
task IAM-003 in docs/WAVE-BUILD-PLAN.md. Dev-mode already works locally with no Entra. Caveat:
OIDC egress only trusts public-HTTPS issuers (a private-LAN Keycloak needs a public HTTPS
endpoint or a small address-policy change).

## THE GOAL (unchanged)
Send ONE real phishing-simulation email to erik.dierks@gmail.com through the governed
Azure operator console workflow. "Fully built" = realistic AI content (ai-gateway +
Qwen weights) + real delivery (ACS to a real target domain). Both are deployed; we are
driving the first real end-to-end send through the console UI.

## KP-008 — RESOLVED (2026-09-05, commit 894b105); verify in the console first
KP-008 ("audit intent write failed", HTTP 503 on every console create) is FIXED.
ROOT CAUSE: the enqueue statement is
  INSERT INTO transactional_outbox (...) ON CONFLICT (idempotency_key) DO NOTHING
and PostgreSQL's ON CONFLICT requires SELECT on the conflict-arbiter column. kp_operator
was granted the outbox INSERT columns but NO SELECT, so the ON CONFLICT clause was denied
and surfaced (misleadingly) as "permission denied for table transactional_outbox". It was
NEVER about Azure, grantor identity, SET ROLE persistence, non-superuser admin, or
ownership -- it reproduced on a stock postgres:16 with a SUPERUSER admin. Isolation on
real postgres: plain INSERT -> OK; INSERT ... ON CONFLICT -> denied; add table SELECT ->
OK; add column SELECT on idempotency_key alone -> OK.
FIX: scripts/azure_migrate.py grants each enqueueing role
  GRANT SELECT (idempotency_key) ON public.transactional_outbox TO <role>
alongside the INSERT columns. Column-scoped so payload/origin_role stay unreadable
(verified: kp_operator can enqueue + idempotent-retry, but SELECT payload/origin_role
still denied). The migration also has a post-commit RUNTIME PROBE (commit df6bbb2): it
connects as fresh kp_operator/audit_writer logins over the real DSN and actually runs the
enqueue INSERT + kp_outbox_health(), failing the deploy with the exact denial if either
can't -- this is the authoritative gate (an in-transaction has_column_privilege check runs
as admin and reads true while a fresh session is denied). Landed via deploy run
33970611034 (verify-images + probe passed against a real postgres).
FIRST NEXT STEP: after the OIDC re-patch, log in and create the Source (SANS ISC:
base_domain=isc.sans.edu, source_type=rss, fetch_path=/rssfeed.xml). It should now
succeed with no KP-008. Then drive the content-authoring -> real-send flow below.

Two EARLIER theories were WRONG and were dropped (do not revisit): (1) "SET ROLE-as-owner
grant does not persist to runtime" -- a fable review showed ALTER TABLE OWNER rewrites the
grantor and Postgres ignores grantor in privilege checks; (2) the ownership-flip fix
(commit e370679) was a no-op producing a byte-identical ACL.

## TEMP DIAGNOSTIC TO REMOVE (cleanup)
- packages/database/src/kp_database/audit_store.py: the `audit_intent_write_failed_detail`
  logging block in record() (logs error_type/error_detail). It surfaced the exact DB
  error that cracked KP-008; remove it now that the cause is known (keep it only until you
  confirm a clean Source-create in the console).
- scripts/azure_migrate.py: the SELECT(idempotency_key) grant and the post-commit runtime
  probe are the real fix -- KEEP them.

## AZURE DEPLOY PROCEDURE (every workloads deploy)
1. Re-enable ACR public network (terraform re-locks it each apply):
   az acr update --name acrkpstaging --public-network-enabled true
2. Ensure HEAD == origin/main, then dispatch:
   bash scripts/operator/deployment-preflight/dispatch-staging-workloads.sh
3. It pauses at the staging required-reviewer gate. The APPROVAL API IS BLOCKED FOR THE
   ASSISTANT — hand the operator: gh api repos/ELDSRQ/kingphisher-phoenix/actions/runs/
   <RUN_ID>/pending_deployments -X POST -F 'environment_ids[]=<ENV_ID>' -f state=approved
   (get ENV_ID from .../pending_deployments). Poll runs/<RUN_ID>/pending_deployments and
   the deploy job's "Migrate and qualify" step.
4. AFTER EVERY DEPLOY the operator OIDC env reverts and MUST be re-patched (login breaks
   otherwise). Re-patch and wait for the new revision healthy:
   az containerapp update --name ca-kp-staging-operator -g rg-kp-staging --set-env-vars \
     "OPERATOR_API_OIDC_SCOPES=openid profile api://97466174-d0ac-460c-94e8-7b6ff3c83da5/console" \
     "OPERATOR_API_OIDC_AUDIENCE=97466174-d0ac-460c-94e8-7b6ff3c83da5"
   (deploy resets OIDC_AUDIENCE to "kp-operator-api" and clears OIDC_SCOPES.)
5. Local gates before dispatch: `make lint` and
   `uv run --frozen --no-sync python -m pytest packages/database/tests/test_migrations_azure_bootstrap.py -q`
   (14 tests incl. the fallback test). The migration bootstrap tests are MOCK-based
   (assert emitted SQL, NOT that grants take effect) — a known blind spot that hid grant
   bugs; the _Connection fake now has outbox_grant_landed / simulate_primary_grant_fails.

## CONSOLE ACCESS + OIDC (all working, but note the gotchas)
- Console UI: https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io/console/
  (root path 404s — the SPA is mounted at /console/).
- Entra OIDC only, no password path. Client app appId 97466174-d0ac-460c-94e8-7b6ff3c83da5
  (SP objectId 87819ee1-0699-4ce7-87ae-b0ac6ae5c463; this app is ALSO the Event Grid
  audience). Tenant 808f2f63-5b2c-46e6-ace7-d133a2df35f8.
- IDENTITY MISMATCH (resolved, but re-check if console is blank): the console derives
  capabilities from the token `roles` claim and FAILS CLOSED. The `administrator` app role
  (appRoleId f1bd33de-fa2e-5886-afeb-1b490f02b9ff) is assigned to user object
  eacd7c6c-7a67-4b0d-9711-5d301d51244f = erik.dierks@gmail.com (#EXT#). If you SSO in as
  licensing@erikdierksgmail.onmicrosoft.com (object ee54cb16-...), roles=[] -> blank
  console (only refresh + sign out render). FIX: sign in as erik.dierks@gmail.com, OR grant
  administrator to the account you sign in with (az rest POST to
  servicePrincipals/87819ee1-.../appRoleAssignedTo). administrator grants ALL capabilities.
  Verify with GET /api/v1/console/session -> should show roles:["administrator"].
- SESSION TOKEN HAS NO REFRESH: the session cookie stores the raw Entra access token and
  re-verifies exp on every request (auth.py ~358, no leeway). After the access token
  expires (~1h) /session returns KP-002 "invalid or expired token" until re-login. This is
  a known limitation, not a bug to chase — just re-login. (Future hardening: refresh flow.)

## CONTENT-AUTHORING -> REAL SEND FLOW (do this once KP-008 clears)
1. Sources -> create. Form fields (base_domain wants BARE host, no scheme/path):
   name=SANS ISC, source_type=rss, base_domain=isc.sans.edu, fetch_path=/rssfeed.xml.
   (Other free feeds: URLhaus/ThreatFox from abuse.ch; TheHackerNews
   feeds.feedburner.com/TheHackersNews.)
2. Acknowledge source terms -> ingest the feed -> a threat/source_item appears -> activate.
3. Create a campaign Pattern from the threat -> approve it (APPROVE_PATTERN).
4. The generation worker calls the ai-gateway (Qwen2.5-7B) to produce the email template
   -> approve the template version (APPROVE_TEMPLATE).
5. Create a training lesson/resource.
6. Create the campaign; import erik.dierks@gmail.com as a CANARY recipient
   (campaign_canary_recipients). Full publish needs a 2nd approver (self-approval is
   forbidden) but the CREATOR can run the CANARY send solo — that is the single-user path
   to a real send.
7. Run the canary = the real ACS send to erik.dierks@gmail.com. Verify delivery in the
   delivery worker logs and the recipient inbox. ACS sending domain: mail.floridamanevolved.us
   (verified); gmail.com is in allowed_recipient_domains for this authorized test.

## AZURE ARCHITECTURE (staging, network_mode=private)
- Resource group rg-kp-staging, region eastus2, env suffix calmflower-9463bfc2.
- Container Apps: ca-kp-staging-operator (console+API), -tracking, per-workload workers,
  -ai-gateway (internal :8090 with an ai-llama sidecar :18081 serving Qwen2.5-7B-Q4_K_M,
  image acrkpstaging.azurecr.io/ai-llama, built OOB by build-ai-llama-image.sh; the
  container command is overridden to /app/llama-server). Generation worker wired via
  KP_WORKER_AI_BASE_URL -> ai_endpoint (ai-gateway internal FQDN).
- Postgres Flexible Server (private VNet, UNREACHABLE from the Mac — only the self-hosted
  VNet runner or `az containerapp exec` can reach it). DB kingphisher. Least-privilege
  roles: kp_operator, kp_tracking, kp_worker_* , audit_writer, audit_owner (NOLOGIN, owns
  audit_events/audit_chain_head/audit_integrity_secret/transactional_outbox + the
  SECURITY DEFINER outbox/audit functions). Migration principal = kpadmin (NOT superuser;
  member of audit_owner). Grants provisioned by scripts/azure_migrate.py (runs as the
  caj-...-migration container job image, command python /app/scripts/azure_migrate.py).
- Deploy runs on a self-hosted runner labeled [self-hosted,linux,azure-vnet]. The
  azure-deploy.yml workflow is SHA-256 pinned across 12 files (EXPECTED_WORKFLOW_SHA256);
  ANY workflow edit requires recomputing `shasum -a 256 .github/workflows/azure-deploy.yml`
  and sed-replacing old->new in all 12 files, then running
  tests/test_external_worker_handoff_contract.py.
- Event Grid ACS delivery-receipt subscription is live (acs-delivery-receipts,
  provisioningState Succeeded). Two-stage ACS; the acs_delivery subscription re-create is
  allowlisted in main.tf's refuse gate.
- Deployed config lives in scripts/operator/deployment-preflight/dispatch-staging-workloads.sh
  (entra ids, fqdns, allowed_recipient_domains=...,gmail.com, ai_endpoint, ACS domain).

## DOCKER .140 -> .105 MIGRATION (DONE + .140 RETIRED)
- The LOCAL Docker qualification/e2e worker was migrated off .140 (macOS/Colima, user
  edierks) to .105 (Windows 11 / WSL2 Ubuntu root, user erikd = erikd@192.168.1.105).
  Azure never involved .140 at runtime. .105 is self-contained: e2e 8/8, base-image qual,
  hermetic all green there.
- Reaching .105: ssh lands in Windows cmd; Docker is in WSL2 -> run everything via
  `ssh erikd@192.168.1.105 "wsl -e bash -s" < script`. .105 runs as root (no sudo).
- Worker selection: scripts/operator/lib/docker-worker.sh. KP_DOCKER_WORKER picks the
  worker; profiles local / wsl105 / mac140. Unset/auto autodetects (local daemon -> local,
  else KP_DEFAULT_REMOTE_WORKER). As of commit fff07ce, KP_DEFAULT_REMOTE_WORKER DEFAULTS
  TO erikd@192.168.1.105 (was edierks@192.168.1.140). So .140 is no longer any default.
- CONCERN/legacy: the three scripts/operator/remote-docker-worker/{stage-remote,
  checkpoint-remote,preflight}.sh are macOS-Keychain identity-transfer helpers that CANNOT
  run against a WSL2 host. They now FAIL FAST as retired legacy (their .140 target reachable
  only via KP_ALLOW_LEGACY_MAC140=1). Do not use them for .105.
- No remaining .140 dependency for the build. .140 remains physically untouched as a
  rollback (flip KP_DOCKER_WORKER=edierks@192.168.1.140 / set KP_ALLOW_LEGACY_MAC140=1).
  test-docker-worker.sh passes and asserts the new .105 default.

## KEY COMMITS (2026-09-05 KP-008 / .105 session — historical; the 2026-09-06 wave is summarized at the top)
- e370679 fix(db): KP-008 outbox grant verify + ownership-flip fallback (+ mock test).
- fff07ce worker: retire .140, default remote worker -> erikd@192.168.1.105.
- 1322f37 (superseded by e370679) earlier broken DIAG-print version of the migration.
- (2026-09-06 wave, all pushed) be5df96 RED batch DEL-002/AUT-002/PLT-002; daff209 AUD-003;
  d192516 TST-002; d254e9c AI-016+ARC-002-Ph1; 93695b4 UX-011 (+§2a srcdoc revert);
  e47570f AI-016 managed auth + UX-011 §2a safe summary. See docs/WAVE-BUILD-PLAN.md.

## OPERATING NOTES
- Operator instructions must be LITERAL: exact paths/hosts/URLs/commands; commands go in
  code blocks; never "supply your inputs".
- Docker never runs locally on the Mac; localhost URLs on the Mac fail unless a tunnel is up.
- The operator drives the browser/console; the assistant cannot approve deploy gates, run
  container exec, or make Entra appRoleAssignments (classifier-blocked) — hand the operator
  exact commands for those.
```
