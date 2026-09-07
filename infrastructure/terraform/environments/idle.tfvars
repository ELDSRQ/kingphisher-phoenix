# idle.tfvars — reproducible "cost-idle" posture (Tier 2 OFF, Tier 1 ON).
#
# WHAT THIS IS
#   An opt-in OVERRIDE var-file layered ON TOP of environments/staging.tfvars.
#   It drives the expensive on-demand tier (Container Apps, ACR, Enterprise Redis,
#   ai-gateway, CI runner VM) to ~$0 while leaving the real-send slice
#   (ACS / verified domain / public DNS / Entra app) untouched and up. It exists so
#   the idle posture is ONE reproducible `terraform apply` instead of a pile of ad-hoc
#   `az` commands that the next deploy silently undoes.
#
# HOW TO APPLY — use the wrapper, not a bare terraform command:
#
#   scripts/operator/azure-idle.sh stop
#
#   A bare `terraform apply -var-file=... environments/idle.tfvars` in this directory
#   CANNOT work, and the wrapper exists because of exactly that:
#     * versions.tf declares `backend "azurerm" {}` with no values, so `terraform init`
#       must be given resource_group_name / storage_account_name / container_name / key.
#       They are GitHub ENVIRONMENT variables TF_STATE_* on the staging environment
#       (see .github/workflows/azure-deploy.yml, "Initialize Terraform").
#     * 13 variables in variables.tf have no default and are not in staging.tfvars.
#       They come from the reviewed deployment configuration — the CONFIG='{...}' line in
#       scripts/operator/deployment-preflight/dispatch-staging-workloads.sh.
#     * the ACS readiness strings in that configuration must be replaced by a FRESH live
#       control-plane readback, or azurerm_communication_service_email_domain_association
#       and azurerm_email_communication_service_domain_sender_username (both
#       prevent_destroy) drop to count 0 and terraform refuses the whole plan.
#   azure-idle.sh does all three, then shows the plan and waits for you to type 'yes'.
#
#   Review the plan: it must destroy ONLY Container Apps + ACR + Redis (+ their private
#   endpoints / role / secret / ACR-pull role assignments, the ACS delivery Event Grid
#   system topic and the custom ACS sender role) and show NO destroy/replace of Postgres,
#   the Key Vault, the audit storage or the ACS email domain. The exact 20-resource
#   destroy set is listed in docs/AZURE-IDLE.md.
#
# PREVIOUSLY BLOCKED, NOW FIXED (2026-09-07). `deploy_data_plane=false` could not even be
#   planned: local.secret_values correctly drops `redis-url`, but local.common_secrets and the
#   local.workload_secret_access for_each both indexed azurerm_key_vault_secret.runtime
#   ["redis-url"] unconditionally, so terraform failed with "Invalid index" before producing a
#   diff. main.tf now merges redis-url into common_secrets only when local.data_plane, and
#   filters workload_secret_access against keys(local.secret_values) — general, so any future
#   conditionally-created secret is handled too. Verified: the idle posture now plans.
#
# WARNING — precedence: the GitHub Actions `workloads` phase hardcodes CLI
#   `-var="deploy_workloads=true"` (and `deploy_ai_gateway`), and a CLI `-var` OUTRANKS
#   any `-var-file`. So this file takes effect ONLY through a DIRECT terraform apply
#   (as above / azure-idle.sh), never by dispatching the workloads workflow. Keeping it
#   in a committed var-file is what makes the idle posture reproducible and reviewable.

# App tier: destroy the operator/tracking/worker/migration Container Apps (and, with the
# ACR/Redis below gone, they cannot run anyway). Removes the always-on replica charge —
# operator/tracking never scale to zero.
deploy_workloads = false

# Freely-destroyable data infra (Path B): drop the Premium container registry + Enterprise
# managed Redis (+ their private endpoints, the redis-url secret, and the ACR-pull role).
# Required to be false here because deploy_workloads=false alone would still keep ACR+Redis.
# (Validation: deploy_workloads=true would REQUIRE this be true, so keep both false together.)
deploy_data_plane = false

# Internal Qwen generation gateway (kp-ai-gateway + baked ai-llama sidecar): off. It is a
# workload, so it is moot while deploy_workloads=false, but pin it false so a later partial
# resume cannot silently rebuild the large ai-llama image.
deploy_ai_gateway = false

# Self-hosted GitHub Actions runner VM inside the VNet: off. CI runs on the local worker,
# so this always-on VM is pure idle cost. (Note: the CI runner flag is normally supplied via
# TF_VAR_deploy_ci_runner from the workflow; pinning it here keeps a direct apply idle too.)
deploy_ci_runner = false

# ---------------------------------------------------------------------------------------
# NOT gated by any flag — do these SEPARATELY to reach true idle:
#
#   PostgreSQL carries lifecycle { prevent_destroy = true } (data protection), so it is
#   NOT gated by deploy_data_plane and this file cannot idle it. Stop it out-of-band —
#   this removes the D2ds_v5 compute charge (the single biggest lever) while retaining data
#   (~7-day auto-restart):
#       az postgres flexible-server stop -g <rg> -n <server>
#
#   Audit-anchor storage is locked WORM (immutable by design) and is intentionally retained
#   (cheap Standard LRS blob) — do not attempt to destroy it.
#
# Tier 1 stays ON: this file does NOT touch acs_resource_mode, acs_* , acs_dns_zone_id, or
# entra_* — the verified ACS domain / public DNS / Entra app remain up at ~$0 so the next
# real send skips all SPF/DKIM re-verification.
#
# RESUME: `scripts/operator/azure-idle.sh start` re-applies without this file and starts
# Postgres, bringing back ACR + Redis (empty) but NOT the workloads — this file destroys
# the container registry, so every image is gone and the Container Apps have nothing to
# run. Rebuild and re-push them, which also deploys the workloads:
#     scripts/operator/deployment-preflight/dispatch-staging-workloads.sh
# ---------------------------------------------------------------------------------------
