# Next-session resume prompt (copy/paste)

> Copy everything in the fenced block below into a fresh session to resume seamlessly.
> Written 2026-09-05. Repo head at handoff: `e370679` (origin/main).

```
You are resuming the Kingphisher-Phoenix phishing-awareness-platform build. Repo:
/Users/edierks/projects/codex-test/phishing-awareness-platform (branch main, head e370679).

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

## KEY COMMITS THIS SESSION
- e370679 fix(db): KP-008 outbox grant verify + ownership-flip fallback (+ mock test).
- fff07ce worker: retire .140, default remote worker -> erikd@192.168.1.105.
- 1322f37 (superseded by e370679) earlier broken DIAG-print version of the migration.

## OPERATING NOTES
- Operator instructions must be LITERAL: exact paths/hosts/URLs/commands; commands go in
  code blocks; never "supply your inputs".
- Docker never runs locally on the Mac; localhost URLs on the Mac fail unless a tunnel is up.
- The operator drives the browser/console; the assistant cannot approve deploy gates, run
  container exec, or make Entra appRoleAssignments (classifier-blocked) — hand the operator
  exact commands for those.
```
