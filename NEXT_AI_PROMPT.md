# Next AI Session Prompt — Phishing Awareness Platform

> **⚠️ SUPERSEDED by `AI_HANDOFF_2026-09-12.md`** — read that first. The
> "Terraform Azure provider auth" blocker framing below is stale; the live
> campaign goal now sits behind the P0–P3 pipeline redesign (four stacked PRs,
> not yet merged) and the pattern second-approver requirement. Kept as history.

## Context
**Repo:** `/Users/edierks/projects/codex-test/phishing-awareness-platform`
**Head:** see `git log --oneline -3` (main, CI green, pushed)
**Date:** 2026-09-11 end of session

**Primary goal:** Complete Azure live campaign E2E (recipients import → canary → full publish)
**Current blocker:** Terraform Azure provider auth (403 on management.azure.com)

> ### Correction notice — read before touching Terraform
> An earlier version of this prompt told you to add `OPERATOR_API_AUDIT_HMAC_KEY` and
> `KP_WORKER_AUDIT_HMAC_KEY` from the `audit-hmac` secret. **Do not do this.** It
> contradicts the security boundary listed at the bottom of this very file, and:
>
> - it fails `test_audit_signing_root_is_exposed_only_to_migration_identity`, which
>   asserts `"AUDIT_HMAC_KEY" not in operator + workers`, plus
>   `test_anchor_uses_private_blob_networking_and_non_secret_worker_configuration`;
> - the root cause it targeted no longer exists — `resolve_recipient_policy` uses no
>   HMAC at all, `require_audit_hmac_key()` does not exist, and the import path calls
>   `require_recipient_import_digest_key()` since `3ea6fb5`;
> - it would not have worked — `audit-hmac` is in neither the operator's granted secret
>   list nor its container `secret` block.
>
> The 500 was diagnosed correctly **against the running container**, whose image predates
> `3ea6fb5`. The fix is to deploy a current image, not to grant the signing root.

---

## Immediate Required Actions (in order)

### 1. Fix Terraform Azure Provider Auth (BLOCKER)

The `az` CLI itself works (it can read the container apps), so diagnose before reaching
for a service principal. A CLI-works/Terraform-403 split usually means the provider is
not using the CLI credential — most often stale or partial `ARM_*` variables.

```bash
env | grep -E '^ARM_|^AZURE_' || echo "no ARM_/AZURE_ vars set"
az account show --query "{user:user.name,tenant:tenantId,sub:id}" -o json
```

If `ARM_*` vars are set but stale/incomplete, drop them so the provider falls back to the
CLI credential:

```bash
unset ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID ARM_USE_CLI
az account set --subscription 169644fd-c81d-4935-af55-5770f8271022
terraform -chdir=infrastructure/terraform plan -var-file=environments/staging.tfvars -out=tfplan
```

Also check the **backend**: remote state uses a SAS token that expires in ~2h, so a 403
can come from the state backend rather than the provider. `terraform init -reconfigure`
with a fresh SAS fixes that case. Normally all state mutations happen in CI (OIDC
configured); local Terraform is read-only for planning.

### 2. Apply Terraform Changes (after auth fixed)

Pending changes:
- `infrastructure/terraform/main.tf` — defines `recipient-import-digest` in the
  **operator container's `secret` block**. This completes `3ea6fb5`, which created the
  secret, granted the operator RBAC and referenced it as an env var, but never defined
  it in the container's secret block — so the env var pointed at a secret that did not
  exist. `terraform validate` passes regardless (the name is just a string); it fails at
  apply.
- `infrastructure/terraform/environments/staging.tfvars` — `allowed_recipient_domains`

```bash
terraform -chdir=infrastructure/terraform plan -var-file=environments/staging.tfvars -out=tfplan
terraform -chdir=infrastructure/terraform apply tfplan
```

### 3. Verify Env Vars Post-Apply
```bash
az containerapp show -g rg-kp-staging -n ca-kp-staging-operator \
  --query "properties.template.containers[0].env[].name" -o tsv | grep -E 'RECIPIENT_IMPORT_DIGEST|AUDIT_HMAC'
```
Expect exactly one line: `OPERATOR_API_RECIPIENT_IMPORT_DIGEST_KEY`.
If `AUDIT_HMAC` appears, someone reinstated the removed hunks — revert them.

### 4. Roll a current image, then test recipient import

Terraform alone will **not** fix the 500: the deployed image predates `3ea6fb5` and still
calls the old code path.

```bash
TOKEN=$(az account get-access-token --resource "api://97466174-d0ac-460c-94e8-7b6ff3c83da5" --query accessToken -o tsv | tr -d '\n\r')
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "https://ca-kp-staging-operator.calmflower-9463bfc2.eastus2.azurecontainerapps.io/api/v1/recipients/import/preview" \
  -d '{"csv_text":"email\nuser1@gmail.com"}'
```
Expect `200` with a `preview_digest`. The recipient domain must be inside
`KP_ALLOWED_RECIPIENT_DOMAINS` (`erikdierksgmail.onmicrosoft.com,gmail.com` today;
`floridamanevolved.us` added by the pending tfvars change) — otherwise it fails closed on
the allowlist, which is correct behaviour, not a bug.

### 5. Campaign Launch Sequence
1. `POST /api/v1/recipients/import/preview` → `/apply` (apply takes the `preview_digest`)
2. `POST /api/v1/campaigns`
3. `PUT /campaigns/{id}/audience` → `POST /campaigns/{id}/audience/freeze`
4. `POST /campaigns/{id}/submit` (creates canary)
5. Approvals — **needs 3 distinct identities under `enforce`**, or set staging to
   `single-operator`
6. `POST /campaigns/{id}/schedule`
7. Poll `GET /campaigns/{id}/review` until `gate.state="canary_succeeded"`
8. `POST /campaigns/{id}/publish`

---

## Current State Summary

| Component | Status |
|---|---|
| Azure infra | ✅ Deployed healthy (run `34479747420`) |
| Token auth | ✅ Working (`aud=97466174-…`, `scp=console`) |
| DMARC | ✅ In place for `mail.floridamanevolved.us` |
| On-prem E2E | ✅ 8/8 passing (single-operator) |
| Terraform changes | ✅ Pending: `recipient-import-digest` secret block + tfvars allowlist |
| **Terraform auth** | ❌ **BLOCKED** (403 on management.azure.com) |
| `AUDIT_HMAC` env vars | ✅ Correctly absent — **do not add** |
| Import endpoint | ❌ 500 — deployed image predates `3ea6fb5`; needs apply **and** a current image |
| Campaign launch | ⏳ Waiting on above |

---

## Key Files to Know
- `AI_HANDOFF_2026-09-11.md` — full session state, gotchas, security boundaries
- `docs/NEXT_SESSION_HANDOFF.md` — longer history
- `infrastructure/terraform/main.tf` — operator container `secret` block + env map
- `infrastructure/terraform/environments/staging.tfvars` — `allowed_recipient_domains`
- `infrastructure/terraform/tests/test_runtime_contract.py` — the contract that forbids
  giving operator/workers the audit signing root

---

## Security Boundaries (Never Cross)
- ❌ Never grant operator API or workers the audit signing root (`audit-hmac`). API
  replicas stage intent only (`main.py:539`). If something there needs an HMAC, give it
  **its own** key — that is what `3ea6fb5` did for the recipient-import digest.
- ❌ Never "fix" Entra audience by changing shared default — `kp-operator-api` is correct
  for on-prem Keycloak
- ❌ Never run Docker on Mac (`.105` only)
- ❌ Never kill the CROW tunnel (port 8000) or `at-*` / `technology-procurement-dev-*`
  containers — separate projects/agents
- ❌ Never `git add -A` (records worktrees as gitlinks)
- ❌ Never point `DATABASE_URL_TEST` at `kingphisher` DB
- ❌ Never give supervise worker queue-depth scale rule or `min_replicas=0` (OPS-003)
- ✅ Preserve `.env`, `data/`, `data/recovery/`, database volumes, audit state

---

## Quick Verification Commands
```bash
# Git state
git log --oneline -3 && git status --short

# Gates
make lint && make typecheck && make test-unit
uv run python -m pytest infrastructure/terraform/tests/ -q

# On-prem E2E (pin the worker — `auto` picks `local` and skips the tunnels)
KP_DOCKER_WORKER=erikd@192.168.1.105 KP_DOCKER_WORKER_PROFILE=wsl105 \
KP_CONSOLE_PG_CONTAINER=kp-console-postgres-v2 KP_CONSOLE_PG_VOLUME=kp_console_postgres_data_v2 \
bash scripts/operator/e2e/run-e2e.sh

# Azure infra
az containerapp list -g rg-kp-staging -o table
```
