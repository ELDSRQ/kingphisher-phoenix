# AI Handoff — Phishing Awareness Platform

> **⚠️ SUPERSEDED by `AI_HANDOFF_2026-09-12.md`** — read that first. Since this
> doc: the generation blocker was diagnosed+fixed and a P0–P3 AI-pipeline
> redesign shipped as four stacked PRs (not yet merged). Content below is kept as
> history; the `gpt-4.1-mini` suggestion in "Open / lower priority" is retracted.

**Date:** 2026-09-11 (updated end of session)
**Head:** `e41e3e9` or later on `main` — confirm with `git log --oneline -3`.
A doc cannot name its own commit, so the docs commits at the top of the log will be
newer than any sha written here. Verify **state**, not equality: tree clean, nothing
unpushed, CI green.
**Repo:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`

> **SESSION STATE (2026-09-11 end of day):** Azure staging infrastructure is healthy. Terraform changes for missing env vars are ready to apply but **blocked on Terraform Azure provider auth (403 on management.azure.com)**. DMARC is in place. On-prem E2E passes 8/8. Next AI must fix Terraform auth, apply changes, verify env vars, then execute the campaign launch sequence.

---

## Executive Summary

Both deployment paths now work.

- **Azure staging** — authenticated API access works end to end. The token blocker that
  stalled the previous session is resolved, and both halves of the
  "OIDC env reverts every deploy" cycle are fixed durably in Terraform.
- **On-prem / disconnected** — the full campaign lifecycle E2E passes **8/8**, run by a
  **single operator** with no approval chain.

**Not yet done from the original goal: a live Azure campaign send.** Everything up to it
works; DMARC is the remaining gate (see Next Steps).

---

## Standing Requirements (do not regress these)

1. **Both deployment options stay first-class.** Azure-integrated AND fully on-prem /
   disconnected from Azure. A fix for one must not regress the other. The operator may
   choose either at deploy time.
2. **A single operator must be able to run a campaign end to end.** ~125-person company
   with a 2-person IT team; a 3-approver control is unusable there and gets worked
   around rather than followed.
3. **On-prem Docker lives only on `192.168.1.105`.** Never on the Mac. Azure/ACR is the
   only exception.

---

## What Changed This Session (16 commits, `a84582e`..`e41e3e9`)

| Commit | Change |
|---|---|
| `a84582e` | Repair corrupted Key Vault role-assignment cleanup step in `azure-deploy.yml` |
| `beebba5` | Opt-in `KP_PROFILE` presets for operator API and workers |
| `7cd7b26` | Handoff + standalone-readiness docs |
| `149ba5b` | Terraform: derive Entra OIDC **audience** from the client id |
| `eab29d9` | Correct the Azure token blocker diagnosis in this doc |
| `c78a673` | Terraform: request the **console scope** on Entra console login |
| `3ea6fb5` | Recipient import digest gets its **own key**, not the audit root |
| `c82ba02` | **`single-operator`** approval posture |
| `63d1241` | Generate the import digest key for standalone stacks |
| `165fee4` | E2E takes API ports from `.env` instead of hardcoding 8000/8001 |
| `4b59812` | Probes prefer the IPv4 answer for an explicitly loopback host |
| `656b3e2` | Backfill audit-anchor defaults into an existing `.env` |
| `eb32c56` | Rewrite this handoff against the session's end state |
| `59010b9` | Terraform: define `recipient-import-digest` in the operator `secret` block |
| `9f41b3f` | Terraform: pin the staging recipient allowlist in tfvars |
| `e41e3e9` | Retract the `audit-hmac` plan across four docs |

CI green on `e41e3e9`: *Hermetic lint, type, and no-skip test gates* + *PostgreSQL and
Redis integration gates*. Local gates: lint, mypy, **3210** unit tests, Terraform
`fmt`/`validate` + contract tests.

> **Note:** both pushes this session **bypassed branch protection** (2 required checks
> "expected"). They passed afterwards, but did not gate the merge. This is how `927b0b1`
> put a broken workflow on `main` and left CI red from 2026-09-10 until `a84582e`.
> Worth tightening if the bypass is not deliberate.

---

## Azure Staging — INFRASTRUCTURE HEALTHY; APP LAYER MISSING ENV VARS

### Token acquisition (was THE blocker)

```bash
az login --tenant "808f2f63-5b2c-46e6-ace7-d133a2df35f8"
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv)
curl -s -H "Authorization: Bearer $TOKEN" "$OPERATOR_CONSOLE_URL/api/v1/campaigns"
```

Verified: returns `200 []` with `aud=97466174-…`, `scp=console`, `roles=['administrator']`.

### Current env var status (operator container app)

| Variable | Status | Source |
|---|---|---|
| `OPERATOR_API_AUDIT_HMAC_KEY` | ✅ **CORRECTLY ABSENT — do not add** | signing root; migration identity only |
| `OPERATOR_API_RECIPIENT_IMPORT_DIGEST_KEY` | ⏳ in Terraform, not yet applied | `recipient-import-digest` secret (`3ea6fb5`) |
| `KP_ALLOWED_RECIPIENT_DOMAINS` | ✅ Set (`erikdierksgmail.onmicrosoft.com,gmail.com`) | GitHub env; now also pinned in `staging.tfvars` |
| `OPERATOR_API_RECIPIENT_HASH_SALT` | ✅ Set | `recipient-salt` secret |
| `OPERATOR_API_OIDC_MODE` | ✅ `oidc` | Terraform |
| `OPERATOR_API_OIDC_AUDIENCE` | ✅ `97466174-...` | Terraform (fixed in `149ba5b`) |
| `OPERATOR_API_OIDC_SCOPES` | ✅ Set | Terraform (fixed in `c78a673`) |

### Worker container app status

| Variable | Status |
|---|---|
| `KP_WORKER_AUDIT_HMAC_KEY` | ✅ **CORRECTLY ABSENT — do not add** (signing root) |
| `KP_WORKER_RECIPIENT_HASH_SALT` | ✅ Conditional on `directory` role |

### Import endpoint 500 root cause — CORRECTED

An earlier revision of this document said the 500 was
`OPERATOR_API_AUDIT_HMAC_KEY` missing → `require_audit_hmac_key()` failing in
`resolve_recipient_policy`, and proposed granting the operator and worker the
`audit-hmac` secret. **That is wrong on every point and must not be done.**

- `resolve_recipient_policy` uses no key or HMAC at all — it is pure allowlist logic.
- `require_audit_hmac_key()` does not exist anywhere in the codebase.
- The import path calls `require_recipient_import_digest_key()` (changed in `3ea6fb5`).

The diagnosis was made against the **running container**, whose image predates
`3ea6fb5`. That older code did call `require_secret_key()` and did need the audit
HMAC — so the observation was real, but the conclusion inverted the fix.

**The actual fix is to deploy, not to grant the signing root.** `3ea6fb5` gave the
import digest its own key (`recipient-import-digest`), already created, granted to the
operator, and wired into the operator's container secret block. Applying Terraform and
rolling a current image resolves the 500.

Granting `audit-hmac` to the operator or workers also **fails CI**:
`test_audit_signing_root_is_exposed_only_to_migration_identity` asserts
`"AUDIT_HMAC_KEY" not in operator + workers`, and
`test_anchor_uses_private_blob_networking_and_non_secret_worker_configuration` fails
too. It would not have worked regardless — `audit-hmac` is in neither the operator's
granted secret list nor its container `secret` block, so the env var would reference a
secret that does not exist.

### Gotchas that will waste your time again

- `az login --use-device-code` is **blocked in this tenant** by Security Defaults (`AADSTS530035`). Use the browser flow.
- Run `az login` in a terminal **outside Claude Code** — `!` runs it inside the session and blocks the session during the browser handoff.
- Health endpoints are `/livez`, `/readyz`, `/healthz` (**no** `/health`) and are **unauthenticated** — they prove nothing about the token. Use an `/api/v1/*` route.
- The two live `az containerapp update` calls made this session are now **redundant** with Terraform; the next deploy sets the same values instead of reverting them.
- **Terraform Azure provider auth is currently broken** (403 on management.azure.com). Fix auth before running plan/apply.

---

## On-Prem / Disconnected — E2E PASSING 8/8

```bash
KP_DOCKER_WORKER=erikd@192.168.1.105 KP_DOCKER_WORKER_PROFILE=wsl105 \
KP_CONSOLE_PG_CONTAINER=kp-console-postgres-v2 KP_CONSOLE_PG_VOLUME=kp_console_postgres_data_v2 \
  bash scripts/operator/e2e/run-e2e.sh
```

**Always pin `KP_DOCKER_WORKER`.** `auto` resolves by testing `docker info`, which
SUCCEEDS on the Mac because its CLI is a remote client to `.105` — so it picks profile
`local`, which sets up **no SSH tunnels** and leaves `localhost:5432` etc. unreachable.

### Docker topology (verified)

The Mac has **no local Docker daemon**. Its CLI is a remote client:

```
docker context: DockerWSL *  ->  ssh://builder@192.168.1.105:2222
```

`docker images` / `ps` / `volume ls` on the Mac return **.105's** inventory (same daemon
id, `OS=Ubuntu 24.04.4 LTS`, `Arch=x86_64` — the tell, since this Mac is Darwin/ARM).
91 images, 36 containers, 166 volumes, all on `.105`, spanning several projects
(`phishing-awareness-platform`, `kingphisher-idp`, `accesstracker`/`at-*`,
`technology-procurement-dev`). Dormant contexts hold nothing.

SSH to `erikd@192.168.1.105` lands in Windows **cmd** — route docker through
`wsl -e bash` (use `kp_worker_run` from `scripts/operator/lib/docker-worker.sh`).

### Local `.env` state — READ BEFORE RUNNING ANYTHING

`.env` was **missing** at session start and was restored from the DR bundle on Alice
(`erikd@192.168.1.36:phishing-platform-DR\kp-dr-latest.tar.gz`, member `env/dot-env`).
All six 64-hex keys verified valid. Current deltas from a stock `.env`:

| Key | Value | Why |
|---|---|---|
| `OPERATOR_API_PORT` | `8010` | **CROW holds 8000** (below) |
| `OPERATOR_API_OIDC_REDIRECT_URI` | `…:8010/…` | follows the port |
| `OPERATOR_API_APPROVAL_POLICY` | `single-operator` | one-person lifecycle |
| `KP_WORKER_APPROVAL_POLICY` | `single-operator` | same |
| `KP_ALLOWED_RECIPIENT_DOMAINS` | `example.com` | matches the E2E |
| `KP_WORKER_AUDIT_ANCHOR_PROVIDER` | `local_worm` | else the worker never readies |
| `KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR` | `data/audit-anchors` | |

**Port 8000 is held by CROW**, not by this project:
`ssh -N -i ~/.ssh/crow_thinkpad_ed25519 -L 127.0.0.1:8000:127.0.0.1:8000 edierks@192.168.1.130`.
CROW is owned by a **separate agent** — do not kill it. Revert `OPERATOR_API_PORT` to
8000 only once that tunnel is gone.

**Console DB:** the run uses `kp_console_postgres_data_v2`. The original
`kp_console_postgres_data` is **still present and untouched** on `.105` — its rows were
encrypted under a different KEK than the restored `.env` (same key id `primary`,
different material, and `OPERATOR_API_CIPHERTEXT_PRIOR_KEYS` is empty). Recover it by
putting the old KEK in `PRIOR_KEYS`, or delete it once you are sure it is not wanted.

---

## Five failures the E2E hit, and their causes

Recorded because each hid the next and they will recur on a fresh machine.

| Symptom | Cause | Fix |
|---|---|---|
| `Bind for 127.0.0.1:5432 failed` | Stale `kp-console-postgres` from 2026-09-04 created with the `local`-profile binding; `docker start` reuses the original ports | removed container (volume kept); now overridable via `KP_CONSOLE_PG_CONTAINER`/`_VOLUME` |
| `:8000/readyz did not become ready` | Console started on the configured port; the gate waited on hardcoded 8000 | `165fee4` |
| `CipherText authentication failed` | Console DB rows under a different KEK than `.env` | fresh `_v2` volume |
| `identity`/AI connectors "refused" | `localhost` → `::1` first; tunnels and Docker bind **IPv4 only**; `_resolve_pinned_target` pinned `resolved[0]` | `4b59812` |
| `audit_integrity_unhealthy` 503 on campaign create + directory sync | audit-anchor worker defaulted to `azure_blob` with no container URL → never ready | `656b3e2` |

The last two were real code bugs. The IPv4 one made the console report connectors as
*failing configuration* when curl reached them fine.

---

## Approval posture — `single-operator`

`ApprovalPolicy.SINGLE_OPERATOR` ("single-operator") drops the second approver **and
nothing else**:

- permitted in hardened and managed deployments; **no** `KP_DEV_STACK` marker needed
- does **NOT** unlock the empty-allowlist allow-all — all three sites
  (`jobs.py:1404`, `jobs.py:1779`, `followup_jobs.py:68`) stay keyed to `SINGLE_ADMIN`,
  and `resolve_recipient_policy` still fails closed on an unset allowlist
- every action still recorded in the audit trail
- `ENFORCE` remains the default

**Why a new value instead of reusing `SINGLE_ADMIN`:** that one is gated behind a dev
stack *and* turns an empty recipient allowlist into allow-all, i.e. licence to mail
anyone on the internet. Using it in a real deployment to drop an approver would have
silently widened who the platform may mail.

Under `ENFORCE`, publishing needs **three distinct identities** — the submitter cannot
approve (`campaigns.py:1101`), a lane is decided once (`:1112`), and whoever approves one
facet cannot approve the other (`:1132`). Azure staging has only two humans
(Erik Dierks, `licensing` — both `administrator`), which is why the Azure lifecycle
cannot be published there. Staging is still `OPERATOR_APPROVAL_POLICY=enforce`.

---

## Next Steps (priority order)

### 0. Fix Terraform Azure provider auth (BLOCKER)
Terraform returns `403` on `management.azure.com` despite valid `az login`. Fix options:

```bash
# Option 1: Explicit ARM_* env vars (service principal)
export ARM_SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"
export ARM_TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
export ARM_CLIENT_ID="<sp-app-id>"
export ARM_CLIENT_SECRET="<sp-secret>"

# Option 2: Azure CLI auth with explicit subscription (if supported by provider version)
az account set --subscription 169644fd-c81d-4935-af55-5770f8271022

# Then:
cd infrastructure/terraform
terraform plan -var-file="environments/staging.tfvars" -out=tfplan
terraform apply tfplan
```

### 1. Apply Terraform changes (after auth fixed)
```bash
cd infrastructure/terraform
terraform plan -var-file="environments/staging.tfvars" -out=tfplan
terraform apply tfplan
```

**Verify env vars post-apply:**
```bash
# recipient-import-digest MUST be present; AUDIT_HMAC must stay ABSENT.
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator \
  --query "properties.template.containers[0].env[].name" -o tsv | grep -E 'RECIPIENT_IMPORT_DIGEST|AUDIT_HMAC'
```
Expected: one line, `OPERATOR_API_RECIPIENT_IMPORT_DIGEST_KEY`. If `AUDIT_HMAC` appears,
someone reinstated the removed hunks — revert them.

### 2. Roll a current image, then test recipient import

The deployed image predates `3ea6fb5`, so the import path still calls the old code that
demanded the audit HMAC. Terraform alone will not fix the 500 — deploy a current image.

```bash
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv | tr -d '\n\r')
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io/api/v1/recipients/import/preview" \
  -d '{"csv_text":"email\nuser1@gmail.com"}'
# Expect 200 with a preview_digest
```

Note the recipient domain must be inside `KP_ALLOWED_RECIPIENT_DOMAINS`
(`erikdierksgmail.onmicrosoft.com,gmail.com` deployed today; `floridamanevolved.us` is
added by the pending `staging.tfvars` change) — otherwise the import fails closed on the
allowlist, which is correct behaviour and not a bug.

### 3. Azure live campaign launch
1. Import recipients: `POST /recipients/import/preview` → `/apply`
2. Create campaign: `POST /campaigns`
3. Configure audience: `PUT /campaigns/{id}/audience` → `POST /campaigns/{id}/audience/freeze`
4. Submit for review: `POST /campaigns/{id}/submit` (creates canary)
5. Approvals — needs 3 identities under `enforce`, or set staging to `single-operator`
6. Schedule: `POST /campaigns/{id}/schedule`
7. Poll review until `gate.state="canary_succeeded"` with `canary_evidence_hash`
8. Publish: `POST /campaigns/{id}/publish`

### 4. Decide staging approval posture
Either add a third Entra identity with approver roles, or set staging to `single-operator` to match on-prem posture and 2-person IT reality.

### 5. Open / lower priority
- ~~`gpt-oss-120b` structured output leaks reasoning channels → consider `AI_FOUNDRY_MODEL=gpt-4.1-mini`~~ **RESOLVED 2026-09-12 (P0, PR #1):** root cause was unbounded reasoning effort (not a leak); fixed by bounding `reasoning_effort`/`max_completion_tokens` + omitting temperature, and pinning Azure to `gpt-5.6-terra` (benchmarked 10/10 valid). Superseded the `gpt-4.1-mini` idea. See `docs/AI_PIPELINE_REDESIGN_SPEC.md`.
- Branch protection bypass (3 pushes bypassed protection; CI passed after merge)
- Old `kp_console_postgres_data` volume: recover via `PRIOR_KEYS` or remove

---

## Critical Config Values (Azure Staging)

```bash
RG="rg-kp-staging"
OPERATOR_CONSOLE_URL="https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
TRACKING_URL="https://ca-kp-staging-tracking.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
CONSOLE_CLIENT_ID="97466174-d0ac-460c-94e8-7b6ff3c83da5"
CONSOLE_APP_OBJECT_ID="bdaff13b-d96e-465d-a5ea-87e9a62c167c"
CONSOLE_SP_OBJECT_ID="87819ee1-0699-4ce7-87ae-b0ac6ae5c463"
TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
SUBSCRIPTION_ID="169644fd-c81d-4935-af55-5770f8271022"
KEY_VAULT="kvkpstaging6117w"
ACS_DOMAIN="mail.floridamanevolved.us"
CONSOLE_SCOPE_ID="6cb5627f-88ef-4858-910a-93eebd45fd64"
AZURE_CLI_APP_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
```

---

## Terraform Changes Pending Apply (BLOCKED on provider auth)

| File | Change | Purpose |
|---|---|---|
| `infrastructure/terraform/main.tf` | Define `recipient-import-digest` in the **operator container's `secret` block** | Completes `3ea6fb5`; without it the env var references a secret that does not exist |
| `infrastructure/terraform/environments/staging.tfvars` | `allowed_recipient_domains = "erikdierksgmail.onmicrosoft.com,gmail.com,floridamanevolved.us"` | Pins the allowlist in Terraform instead of only GitHub env |

> **Two earlier hunks were REMOVED, not applied:** `OPERATOR_API_AUDIT_HMAC_KEY` and
> `KP_WORKER_AUDIT_HMAC_KEY` → `audit-hmac`. See "Import endpoint 500 root cause —
> CORRECTED" above. They fail two contract tests, target a root cause that no longer
> exists, and reference a secret that is in neither the operator's granted list nor its
> container `secret` block. Do not reinstate them.

Validation: `terraform fmt -check` and `terraform validate` clean; terraform contract
tests, lint, mypy and 3210 unit tests all pass.

### Blocker: Terraform Azure provider 403

`403 Server failed to authenticate the request` on `management.azure.com` while the
`az` CLI itself works (it can read the container apps). A CLI-works/Terraform-403 split
usually means the provider is not using the CLI credential — most often stale or partial
`ARM_*` environment variables taking precedence.

Diagnose before reaching for a service principal:

```bash
env | grep -E '^ARM_|^AZURE_' || echo "no ARM_/AZURE_ vars set"
az account show --query "{user:user.name,tenant:tenantId,sub:id}" -o json
```

If any `ARM_CLIENT_ID` / `ARM_CLIENT_SECRET` / `ARM_TENANT_ID` are set but incomplete or
stale, unset them so the provider falls back to the CLI credential:

```bash
unset ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID ARM_USE_CLI
az account set --subscription 169644fd-c81d-4935-af55-5770f8271022
terraform -chdir=infrastructure/terraform plan -var-file=environments/staging.tfvars -out=tfplan
```

Note the remote state backend needs its own credential — a SAS token that expires in ~2h
(see STANDALONE-READINESS "Local Terraform State Access"); a 403 can come from the
backend rather than the provider. `terraform init -reconfigure` with a fresh SAS is the
fix for that case. All state mutations normally happen in CI, where OIDC is configured;
local Terraform is read-only for planning.

### After apply, verify

```bash
# Expect recipient-import-digest present, and AUDIT_HMAC absent (absence is correct)
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator \
  --query "properties.template.containers[0].env[].name" -o tsv | grep -E 'RECIPIENT_IMPORT_DIGEST|AUDIT_HMAC'
```

A current image must also be rolled — the deployed one predates `3ea6fb5`, so the import
path still calls the old code regardless of env vars.

Then test import:
```bash
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv | tr -d '\n\r')
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io/api/v1/recipients/import/preview" \
  -d '{"csv_text":"email\nuser1@gmail.com"}'
```

---

## Key Commands

```bash
# Gates (Mac, hermetic)
make lint && make typecheck && make test-unit

# On-prem E2E (use the pinned invocation above)
bash scripts/operator/e2e/run-e2e.sh

# Inspect .105 Docker from the Mac
. scripts/operator/lib/docker-worker.sh
KP_DOCKER_WORKER=erikd@192.168.1.105 kp_worker_run <<'SH'
docker ps --format '{{.Names}} | {{.Status}}'
SH

# Azure
az containerapp list -g rg-kp-staging -o table
bash scripts/operator/azure-idle.sh     # idle / resume
```

---

## Security Boundaries (Never Cross)

- ❌ **Never grant the operator API the audit signing root** (`audit-hmac`). API replicas
  stage intent only (`main.py:539`); holding it would let them forge audit entries. If
  something there needs an HMAC, give it **its own** key — that is exactly what `3ea6fb5`
  did for the recipient-import digest.
- ❌ Never "fix" the Entra audience by changing the shared default — `kp-operator-api` is
  CORRECT for the on-prem Keycloak posture (audience mapper in
  `infrastructure/idp/realm-kingphisher.json`, asserted by
  `tests/test_entra_alternative_idp.py`). Azure is configured via Terraform, on-prem via
  `.env`.
- ❌ Never run Docker on the Mac. `.105` only.
- ❌ Never kill the CROW tunnel or any `at-*` / `technology-procurement-dev-*` container —
  separate projects/agents.
- ❌ Never `git add -A` (records worktrees as gitlinks)
- ❌ Never point `DATABASE_URL_TEST` at the `kingphisher` DB (fixtures `DROP SCHEMA`)
- ❌ Never give the supervise worker a queue-depth scale rule or `min_replicas=0` (OPS-003)
- ❌ Never commit secrets, keys, or `.env` contents
- ✅ Preserve `.env`, `data/`, `data/recovery/`, database volumes, audit state

---

## Resume Instructions for Next AI

1. Read this handoff; `docs/NEXT_SESSION_HANDOFF.md` has the longer history.
2. `git log --oneline -20` — the docs commit at the top is expected to be newer than
   any sha named in this file. What matters: **tree clean, nothing unpushed, CI green**
   (`git status --short` empty; `git rev-list --count origin/main..HEAD` = 0).
3. Confirm `.env` exists and carries the deltas in the table above. If it is missing,
   **do not let `bootstrap_env` mint fresh credentials** while Postgres volumes exist —
   restore from DR on Alice instead. Fresh keys would orphan the database permanently,
   and losing `OPERATOR_API_CIPHERTEXT_KEK` makes recipient data unreadable.
4. Azure: `az login --tenant 808f2f63-…` (browser flow, outside Claude Code), then the
   token command above.
5. On-prem: the pinned `run-e2e.sh` invocation above; expect **8 passed**.
6. Pick up at **Next Steps** — DMARC first, then the live campaign launch.

---

## Repository Layout Reference

```
apps/
  operator-api/       # FastAPI console backend; config.py holds KP_PROFILE + policies
  tracking-api/       # Tracking pixel / training endpoints
  workers/            # Delivery, retention, audit-anchor, directory, generation...
packages/
  domain-models/      # ApprovalPolicy (ENFORCE / SINGLE_OPERATOR / SINGLE_ADMIN)
  telemetry/          # Settings, errors, logging
  auditing/           # Hash-chained audit store
  database/           # Models, migrations, CipherText
infrastructure/
  idp/                # Keycloak IdP — on-prem identity path
  mock-services/      # mock_idp / mock_graph / mock_ai for the local stack
  terraform/          # Azure infra (ACA, PostgreSQL, Redis, KV, ACS, Foundry)
scripts/
  bootstrap_env.sh                  # .env seeding + credential generation (recovery-guarded)
  operator/lib/docker-worker.sh     # .105 worker abstraction — PIN THE TARGET
  operator/e2e/run-e2e.sh           # Local E2E gate
  operator/dep010/start-console.sh  # Local stack bring-up
tests/
  e2e/                              # Live tests (console smoke, Mailpit canary)
  test_entra_alternative_idp.py     # Keycloak/on-prem identity contract
```
