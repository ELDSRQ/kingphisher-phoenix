# AI Handoff — Phishing Awareness Platform
**Date:** 2026-09-11  
**Head:** `37a171b` (main)  
**Repo:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`

---

## Executive Summary

**Azure staging is fully deployed and healthy.** All blocking bugs resolved. On-prem stack is fully E2E tested and independent. Remaining work: **live Azure campaign launch** (recipients import → canary → full publish) which also completes the Azure live E2E gate.

---

## Current State

### ✅ Completed (This Session)
1. **Operator-api config profile defaults bug fixed** — `KP_PROFILE=local-dev` no longer overrides explicit `config_store=managed` / `oidc_mode=oidc` settings
   - Files: `apps/operator-api/src/kp_operator_api/config.py` + 4 test files updated
   - All 1067 operator-api tests pass, mypy strict + ruff clean

2. **Azure infrastructure blockers resolved:**
   - 409 RoleAssignmentExists loop — orphaned `workload_secret` assignments deleted, cleanup step added
   - Audit anchor self-chain collision — layout v2 + skip re-publish when head unchanged
   - ACR public access toggle — automated in workflow
   - Keycloak IdP port conflict — fixed to 8444
   - `audit_writer` password clobber — `KP_POSTGRES_GATE_ALLOW_SHARED_SERVER=1` + reset

### ✅ Azure Staging Deployed & Healthy (run `34479747420`)
| Component | Status |
|-----------|--------|
| Container Apps (4/4) | Running — operator, tracking, worker, ai-gateway |
| `/readyz` | All 200 |
| PostgreSQL Flexible | Running |
| Redis Premium | Running |
| Key Vault | Healthy |
| ACS Email Service | **Verified** — Domain/SPF/DKIM/DKIM2 all Verified |
| Foundry `gpt-oss-120b` | Deployed GlobalStandard, endpoint 200 OK |
| AI Gateway | Path D — no llama sidecar, Entra MI, scale-to-zero, model pin |

### ✅ On-Premises / Local Stack — Fully E2E Tested
| Gate | Result |
|------|--------|
| Hermetic (Mac) | 3163+ passed |
| Postgres Integration (.105) | 99 passed |
| Redis Integration (.105) | 2 passed |
| E2E (.105) | 8/8 passed (console smoke + Mailpit canary) |
| Smoke | 27 passed |
| Keycloak IdP Contract | 23/23 passed |

**Profiles control the stack:**
- `KP_PROFILE=azure` → managed, OIDC, ACS receipts, Key Vault, scale-to-zero
- `KP_PROFILE=local-dev` → dev-auth, single-admin, env_file, Mailpit, supervisor
- `KP_PROFILE=local-hardened` → OIDC, enforce, env_file, Mailpit, supervisor

---

## Critical Config Values (Azure Staging)

```bash
RG="rg-kp-staging"
OPERATOR_CONSOLE_URL="https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
TRACKING_URL="https://ca-kp-staging-tracking.calmflower-9463bfc2.eastus2.azurecontainerapps.io"
CONSOLE_CLIENT_ID="97466174-d0ac-460c-94e8-7b6ff3c83da5"
TENANT_ID="808f2f63-5b2c-46e6-ace7-d133a2df35f8"
ACS_DOMAIN="mail.floridamanevolved.us"
```

---

## Next Steps (Priority Order)

### 1. Complete Azure Live E2E — Campaign Launch
**Prerequisites:** Azure CLI auth + Entra token for console client

```bash
# On machine with az CLI:
az login
az account set --subscription <staging-sub>

# Get token (admin consent needed on app registration 97466174-d0ac-460c-94e8-7b6ff3c83da5)
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv)

# Verify
curl -H "Authorization: Bearer $TOKEN" "$OPERATOR_CONSOLE_URL/readyz"
```

**Campaign flow:**
1. Import recipients via `/api/v1/recipients/import/preview` → `/apply`
2. Create campaign `POST /campaigns`
3. Configure audience `PUT /campaigns/{id}/audience` → freeze `POST /audience/freeze`
4. Submit for review `POST /campaigns/{id}/submit` (creates canary cohort)
5. **Two approvals** `POST /campaigns/{id}/approvals/authorize` (ENFORCE policy)
6. Schedule `POST /campaigns/{id}/schedule`
7. Poll `/campaigns/{id}/review` until `gate.state="canary_succeeded"` with `canary_evidence_hash`
8. Publish `POST /campaigns/{id}/publish`

### 2. DMARC Record (deliverability)
```
_dmarc.mail.floridamanevolved.us  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@floridamanevolved.us; ruf=mailto:dmarc@floridamanevolved.us; fo=1"
```

### 3. Optional: Switch AI Model
If `gpt-oss-120b` structured output quality insufficient (leaks reasoning channels):
```bash
# In GitHub env vars or terraform:
AI_FOUNDRY_MODEL=gpt-4.1-mini  # or other model advertising jsonSchemaResponse
```

---

## Key Files / Commands

### Local Development
```bash
# Full local stack (on .105 WSL2)
scripts/operator/e2e/run-e2e.sh

# Hermetic tests
make test

# Postgres integration (clobbers audit_writer pwd — use gate)
KP_POSTGRES_GATE_ALLOW_SHARED_SERVER=1 scripts/run-postgres-tests.sh
# Then reset audit_writer password

# Typecheck + lint
python -m mypy apps/operator-api/src/kp_operator_api/config.py --strict
python -m ruff check apps/operator-api/src/kp_operator_api/config.py
```

### Azure Operations
```bash
# Idle posture (scale apps to zero, preserve data plane)
scripts/operator/azure-idle.sh idle

# Resume
scripts/operator/azure-idle.sh start

# Terraform state fix (one-time)
gh workflow run azure-tf-state-fix.yml
```

### Key Config Files
- `apps/operator-api/src/kp_operator_api/config.py` — profile defaults logic
- `infrastructure/idp/docker-compose.keycloak.yml` — Keycloak on 8444
- `infrastructure/idp/provision_idp.py` — dotted audience keys, fullScopeAllowed
- `scripts/operator/azure-idle.sh` — idle/resume orchestration
- `.github/workflows/azure-deploy.yml` — deploy pipeline

---

## Known Issues / Gotchas

| Issue | Status | Workaround |
|-------|--------|------------|
| `gpt-oss-120b` structured output leaks reasoning | **Open** | Validate `/propose` end-to-end; switch to `gpt-4.1-mini` via `AI_FOUNDRY_MODEL` |
| Dead workflow steps in `azure-deploy.yml` | **Cleanup needed** | Remove `fedbd75`/`ea51330` steps; re-pin `EXPECTED_DEPLOY_WORKFLOW_SHA256` |
| DMARC NotStarted | **Open** | Add DNS record above |
| Console client needs admin consent for token | **Blocker for E2E** | Grant in Azure Portal → App registrations → API permissions |
| ACR build window | **Handled** | Workflow opens/closes public access per build |

---

## Security Boundaries (Never Cross)

- ❌ Never `git add -A` (records worktrees as gitlinks)
- ❌ Never point `DATABASE_URL_TEST` at `kingphisher` DB (fixtures `DROP SCHEMA`)
- ❌ Never give supervise worker queue-depth scale rule or `min_replicas=0` (OPS-003)
- ❌ Never use `DockerExternal` / `kp-remote-mac` Docker contexts (resolve to shared Desktop)
- ❌ Never commit secrets, keys, `.env` contents
- ✅ Preserve `.env`, `data/`, `data/recovery/`, database volumes, audit state

---

## Resume Instructions for Next AI

1. **Read this handoff** + `docs/NEXT_SESSION_HANDOFF.md` (full history)
2. **Verify Azure state:** `az containerapp list -g rg-kp-staging -o table`
3. **Get Entra token** (admin consent required on console client app)
4. **Run campaign launch sequence** using API endpoints above
5. **Validate live delivery** → inbox receipt → tracking events → campaign report

**If blocked on token:** The console app registration `97466174-d0ac-460c-94e8-7b6ff3c83da5` needs "Grant admin consent" in Azure Portal → Entra ID → App registrations → API permissions. This is a one-time manual step.

---

## Repository Layout Reference

```
apps/
  operator-api/       # FastAPI console backend (config fix here)
  tracking-api/       # Tracking pixel / training endpoints
  worker/             # Delivery, retention, audit-anchor workers
packages/
  kp-domain-models/   # ApprovalPolicy, domain allowlist, RoE
  kp-telemetry/       # Settings, errors, logging
  kp-auditing/        # Hash-chained audit store
infrastructure/
  idp/                # Keycloak IdP (port 8444, start-dev)
  terraform/          # Azure infra (ACA, PostgreSQL, Redis, KV, ACS, Foundry)
scripts/operator/
  azure-idle.sh       # Idle/resume
  e2e/run-e2e.sh      # Local E2E gate
  dep010/start-console.sh  # Local stack bring-up
tests/
  e2e/                # Live tests (Mailpit, Azure smoke)
  test_*_config.py    # Config profile tests
```

---

**Production / RSA Conference = NO-GO** until: exact-final ARM64/AMD64 images, registry attestation, browser/WCAG, cloud/provider, recovery, human acceptance gates pass (per `PRODUCTION-READINESS-TASK-MATRIX.md`).