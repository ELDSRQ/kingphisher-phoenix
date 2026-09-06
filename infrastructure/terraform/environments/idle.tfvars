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
# HOW TO APPLY (direct terraform, NOT the GitHub workloads deploy — see WARNING):
#   cd infrastructure/terraform
#   terraform apply \
#     -var-file="environments/staging.tfvars" \
#     -var-file="environments/idle.tfvars"
#   (plus whatever var-file / TF_VAR_* supplies the no-default vars: subscription_id,
#    operator_fqdn, tracking_fqdn, entra_*, acs_* — e.g. the reviewed .auto.tfvars.json.)
#   Review the plan: it must destroy ONLY Container Apps + ACR + Redis (+ their private
#   endpoints / role / secret) and show NO destroy/replace of Postgres or audit storage.
#   `scripts/operator/azure-idle.sh stop` wraps this apply and the Postgres stop below.
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
# RESUME: re-apply with ONLY staging.tfvars (drop this file) — or azure-idle.sh start —
# and `az postgres flexible-server start` to bring Tier 2 back.
# ---------------------------------------------------------------------------------------
