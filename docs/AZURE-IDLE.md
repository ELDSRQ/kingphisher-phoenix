# Deep Azure idle — `scripts/operator/azure-idle.sh`

The deliberate, operator-driven, plan-reviewed idle. It stops PostgreSQL and applies
`infrastructure/terraform/environments/idle.tfvars`, which **destroys the container
registry, the Enterprise Redis and the Container Apps**.

It is *not* the nightly job. `scripts/operator/azure-nightly-shutdown.sh`
(docs/NIGHTLY-AZURE-SHUTDOWN.md) is the cheap, fast-reversible power-down that runs on a
timer and never touches terraform. This one is the deep idle you run by hand when the
platform is going quiet for a while.

| | nightly shutdown | `azure-idle.sh stop` |
|---|---|---|
| trigger | scheduled, unattended | manual, interactive |
| Postgres | stopped | stopped |
| Container Apps | `--min-replicas 0` | **destroyed** |
| ACR / Redis | untouched | **destroyed** |
| images | keep | **gone — must be rebuilt and re-pushed** |
| terraform | never | plan + typed `yes` + apply |

---

## The command

```bash
scripts/operator/azure-idle.sh preflight   # read-only: prove every precondition
scripts/operator/azure-idle.sh stop        # idle  (plans, then waits for you to type 'yes')
scripts/operator/azure-idle.sh start       # resume ACR + Redis (plans, then waits for 'yes')
scripts/operator/azure-idle.sh status      # read-only inventory
```

`stop` and `start` always print a full terraform plan and stop at:

```
  Type 'yes' to apply this plan:
```

There is deliberately no `--yes`, no `--auto-approve` and no environment variable that
skips it. That confirmation is the only gate in front of a destroy of ACR, Redis and the
Container Apps.

### ACR is destroyed — images must be re-pushed

`stop` deletes the container registry. Every image in it — operator-api, tracking-api,
worker, migration, ai-gateway, ai-llama — is **permanently gone**, digests included. The
resume path is therefore not "apply the workloads back"; it is "rebuild and re-push", which
is what the deploy workflow does:

```bash
scripts/operator/deployment-preflight/dispatch-staging-workloads.sh
```

`azure-idle.sh start` deliberately brings back only ACR + Redis (empty) and leaves
`deploy_workloads=false`, because Container Apps pointing at deleted images come up broken.
`start --workloads` exists for the case where the images are already back in ACR, and it
refuses to run unless all four of `KP_OPERATOR_IMAGE`, `KP_TRACKING_IMAGE`,
`KP_WORKER_IMAGE` and `KP_MIGRATION_IMAGE` are set to digest-pinned references.

---

## Why the script is not just `terraform apply`

A bare `terraform plan` in `infrastructure/terraform` can never work. Three things are
supplied by `.github/workflows/azure-deploy.yml` at run time and by nothing else:

**1. The backend has no configuration.** `versions.tf` declares `backend "azurerm" {}`
(empty). The workflow supplies it at "Initialize Terraform" from GitHub **environment**
variables on the `staging` environment (not repository variables):

```bash
gh variable list --repo ELDSRQ/kingphisher-phoenix --env staging
#   TF_STATE_RESOURCE_GROUP, TF_STATE_STORAGE_ACCOUNT, TF_STATE_CONTAINER
```

with the state key `<environment>/kingphisher.tfstate`. `azure-idle.sh` reads the same
three variables with `gh variable get` and runs the identical `terraform init`. Override
locally with `KP_TF_STATE_RESOURCE_GROUP` / `KP_TF_STATE_STORAGE_ACCOUNT` /
`KP_TF_STATE_CONTAINER` / `KP_TF_STATE_KEY`.

**2. Thirteen variables have no default and are not in `environments/staging.tfvars`:**
`subscription_id`, `operator_fqdn`, `tracking_fqdn`, `entra_tenant_id`, `entra_client_id`,
`acs_sending_domain`, `acs_sender_local_part`, `acs_sender_display_name`,
`acs_daily_message_limit`, `acs_messages_per_minute`, `acs_ramp_batch_size`,
`acs_ramp_interval_seconds`, `allowed_recipient_domains`.

They come from the reviewed deployment configuration. That configuration already exists,
committed and secret-free, as the single `CONFIG='{…}'` line in
`scripts/operator/deployment-preflight/dispatch-staging-workloads.sh` — the same JSON the
deploy workflow consumes. `azure-idle.sh` **reads it out of that file** rather than keeping
a second copy, applies the same deterministic transforms the workflow does (integer
coercion for the four ACS pacing values, `graph_endpoint` / `reported_mailbox_endpoint`
derived from the two `enable_*` flags) and writes a temporary `.tfvars.json` that is
deleted on exit. Point it at a different dispatch script with `KP_DEPLOYMENT_CONFIG_FILE`.

Nothing secret is involved: the workflow rejects any value matching a credential pattern
before Terraform sees it, so this file is safe to keep in git and safe to regenerate.

**3. ACS readiness must be read live, not trusted from the file.** The workflow replaces
every `acs_*_verification_status` and `acs_readiness_checked_at` with a fresh
control-plane readback before Terraform runs. That is not bookkeeping:

```hcl
resource "azurerm_communication_service_email_domain_association" "main" {
  count = local.acs_provision && local.acs_binding_management_enabled && local.acs_domain_live_ready ? 1 : 0
  lifecycle { prevent_destroy = true }
}
```

`acs_domain_live_ready` requires Domain/SPF/DKIM/DKIM2 all `verified` **and**
`acs_readiness_checked_at` within `acs_readiness_max_age_hours` (24) of now. With the empty
strings that are committed in the dispatch script, that count goes to 0 — and because both
that association and the sender username carry `prevent_destroy`, terraform refuses the
entire plan rather than idling anything.

`azure-idle.sh` therefore performs the same read-only readback (`az resource list` to
discover the Email/Communication Services, then `az rest` GETs against
`management.azure.com`) and stamps a current `acs_readiness_checked_at`. It also passes
`-var acs_deployment_stage=workloads`, because at the `"disabled"` default
`acs_binding_management_enabled` is false and those two resources drop out for the same
reason.

---

## What `stop` destroys

Derived from the configuration by diffing the resource set at
`deploy_workloads=true,deploy_data_plane=true` against
`deploy_workloads=false,deploy_data_plane=false`. **20 resources:**

```
Container Apps        azurerm_container_app.operator[0]
                      azurerm_container_app.tracking[0]
                      azurerm_container_app.worker["worker"]
                      azurerm_container_app_job.migration[0]
Registry              azurerm_container_registry.main[0]
                      azurerm_private_endpoint.acr[0]
                      azurerm_role_assignment.acr_pull["operator"|"tracking"|"worker"|
                                                       "migration"|"ai-gateway"]
Redis                 azurerm_managed_redis.main[0]
                      azurerm_private_endpoint.redis[0]
                      azurerm_key_vault_secret.runtime["redis-url"]
                      azurerm_role_assignment.workload_secret["operator:redis-url"]
                      azurerm_role_assignment.workload_secret["tracking:redis-url"]
                      azurerm_role_assignment.workload_secret["worker:redis-url"]
ACS delivery plumbing azurerm_eventgrid_system_topic.acs_delivery[0]
                      azurerm_role_definition.acs_email_sender[0]
                      azurerm_role_assignment.communication_sender["worker"]
```

Two of those are worth calling out because they are not obviously "Container Apps + ACR +
Redis": the **ACS delivery Event Grid system topic** and the **custom ACS email-sender role
definition/assignment** are gated on `deploy_workloads`, so they go too. Neither holds
data; the next workloads deploy recreates both.

Everything else survives, including the things that must never be destroyed:

- `azurerm_postgresql_flexible_server.main` (+ database, configuration) — stopped, not destroyed
- `azurerm_storage_account.audit_anchor`, `azurerm_storage_container.audit_anchor` and its
  locked immutability policy
- `azurerm_key_vault.main` and every other secret in it
- `azurerm_container_app_environment.main`
- the whole ACS slice: communication service, email service, email domain, the domain
  association, the sender username, and the public DNS records
- the VNet, subnets, Log Analytics, and the workload identities

**A plan that shows a destroy or replace of anything in that second list is wrong. Answer
anything other than `yes`.**

---

## Preconditions the preflight checks

`azure-idle.sh preflight` is read-only and fails with one sentence naming what is missing,
never a terraform stack trace. In order:

1. `terraform`, `python3`, `az`, `gh` on PATH.
2. `az login`, and the resource group visible.
3. The `TF_STATE_*` backend triple resolvable from `gh` (or `KP_TF_STATE_*`).
4. **Blob data-plane access to the state container** — see below.
5. **Private data-plane reachability** — see below.
6. The reviewed configuration parses and every no-default variable has a value.
7. The live ACS domain reads back fully `Verified`.
8. `terraform init` succeeds against the real backend.

### Blocker: the operator's Azure login cannot read the state container

Subscription **Owner is a control-plane role**. It does not grant blob *content* access,
and the state account has shared-key auth disabled, so there is no key fallback. Without a
data-plane role `terraform init` dies with an opaque

```
Error: Failed to get existing workspaces: listing blobs: ... 403
AuthorizationPermissionMismatch
```

The preflight detects this and prints the exact grant. It is a **write to Azure RBAC**, so
run it yourself, once:

```bash
az role assignment create \
  --assignee-object-id "$(az ad signed-in-user show --query id -o tsv)" \
  --assignee-principal-type User \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$(gh variable get TF_STATE_RESOURCE_GROUP --repo ELDSRQ/kingphisher-phoenix --env staging)/providers/Microsoft.Storage/storageAccounts/$(gh variable get TF_STATE_STORAGE_ACCOUNT --repo ELDSRQ/kingphisher-phoenix --env staging)"
```

Role propagation takes a minute or two.

### Blocker: `network_mode = "private"` means terraform cannot run from a laptop

This is the same reason CI runs on a self-hosted VNet runner. In private mode the Key
Vault, the audit storage account, Redis and the registry all have
`publicNetworkAccess = Disabled`. Terraform reads **every** `azurerm_key_vault_secret`
through the vault's **data** plane on refresh, and `stop` additionally *deletes* the
`redis-url` secret. From outside the VNet neither works — confirmed from the Mac, where
even `az acr repository list` against `acrkpstaging` returns 403.

So the deep idle must be run **from inside the VNet**, on the self-hosted CI runner VM:

```bash
az vm start -g rg-kp-staging -n "$(az vm list -g rg-kp-staging --query '[0].name' -o tsv)"
# then, on that VM:
KP_INSIDE_VNET=1 KP_KEEP_CI_RUNNER=1 scripts/operator/azure-idle.sh stop
```

`KP_KEEP_CI_RUNNER=1` passes `deploy_ci_runner=true` so the apply does not destroy the VM
it is running on. Deallocate that VM afterwards (the nightly job does it for free):

```bash
az vm deallocate -g rg-kp-staging -n <runner>
```

The preflight refuses to continue from outside the VNet. `KP_INSIDE_VNET=1` is the
acknowledgement that you are already inside it.

---

## Known blocker: redis-url is indexed unconditionally

**`deploy_data_plane=false` cannot be planned today.** It is a configuration bug, not a
credentials or wiring problem, and it is why `environments/idle.tfvars` has never been
plan-verified.

`local.secret_values` in `infrastructure/terraform/main.tf` correctly drops the
`redis-url` Key Vault secret when the data plane is off:

```hcl
local.data_plane ? { redis-url = local.redis_url } : {},
```

but two other places still index it unconditionally, so the plan fails with:

```
Error: Invalid index
  on main.tf line 1114, in resource "azurerm_role_assignment" "workload_secret":
  1114:   scope = azurerm_key_vault_secret.runtime[each.value.secret_name].resource_versionless_id
    each.value.secret_name is "redis-url"

Error: Invalid index
  on main.tf line 1161, in locals:
  1161:     redis-url = azurerm_key_vault_secret.runtime["redis-url"].versionless_id
```

The fix is two hunks in `main.tf` (verified: with them applied, `terraform validate`
succeeds and `deploy_workloads=false deploy_data_plane=false` plans cleanly).

1. Filter `local.workload_secret_access` to secrets that actually exist:

```hcl
  workload_secret_access = {
    for key, value in merge([
      for workload, secret_names in local.workload_secret_names : {
        for secret_name in secret_names : "${workload}:${secret_name}" => {
          workload    = workload
          secret_name = secret_name
        }
      }
    ]...) : key => value if contains(keys(local.secret_values), value.secret_name)
  }
```

2. Make `local.common_secrets` conditional on the data plane:

```hcl
  common_secrets = merge({
    audit-database-url = azurerm_key_vault_secret.runtime["audit-database-url"].versionless_id
    ciphertext-kek     = azurerm_key_vault_secret.runtime["ciphertext-kek"].versionless_id
    recipient-salt     = azurerm_key_vault_secret.runtime["recipient-salt"].versionless_id
    },
    local.data_plane ? {
      redis-url = azurerm_key_vault_secret.runtime["redis-url"].versionless_id
    } : {},
  )
```

Every consumer of `local.common_secrets["redis-url"]` sits inside a resource gated on
`deploy_workloads`, which is always false whenever `deploy_data_plane` is false (the
`deploy_data_plane` validation enforces that pairing), so nothing else has to change.

`azure-idle.sh` recognises this failure and prints the diagnosis rather than leaving the
raw terraform error.

---

## Environment overrides

| variable | default | purpose |
|---|---|---|
| `KP_RG` | `rg-kp-staging` | resource group |
| `KP_ENV` | `staging` | environment name; also selects `environments/<env>.tfvars` and the state key |
| `KP_REPO` | `ELDSRQ/kingphisher-phoenix` | repo whose environment variables hold `TF_STATE_*` |
| `KP_TF_STATE_RESOURCE_GROUP` / `_STORAGE_ACCOUNT` / `_CONTAINER` / `_KEY` | from `gh` | backend, without `gh` |
| `KP_DEPLOYMENT_CONFIG_FILE` | `dispatch-staging-workloads.sh` | where the reviewed `CONFIG='{…}'` is read from |
| `KP_NETWORK_MODE` | `private` | must match the live deployment |
| `KP_INSIDE_VNET` | unset | acknowledge you are inside the VNet |
| `KP_KEEP_CI_RUNNER` | unset | keep the runner VM (set it when idling *from* the runner) |
| `KP_OPERATOR_IMAGE` etc. | unset | required by `start --workloads` |

## Cost

After the Container App revision leak was fixed on 2026-09-07 (76 orphaned replicas
deactivated, both public apps flipped to `revision_mode = "Single"`), the deep idle is
worth roughly **$101/mo** — ACR Premium, Enterprise Redis and the worker app — not the
~$889/mo headline that the revision leak alone accounted for. Stopping PostgreSQL, which
the nightly job already does, remains the single biggest lever. Weigh that $101 against
having to rebuild and re-push every image before the next deploy.

## See also

- `docs/NIGHTLY-AZURE-SHUTDOWN.md` — the cheap, reversible nightly power-down
- `docs/HYBRID-AZURE-LOCAL-PLAN.md` — Path B, the tiering this implements
- `docs/design/AZURE-RESIDENCY-AUDIT-2026-09.md` — where the cost numbers come from
- `infrastructure/terraform/environments/idle.tfvars` — the posture itself
