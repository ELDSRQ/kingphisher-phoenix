# Deep Azure idle — `scripts/operator/azure-idle.sh`

The deliberate, operator-driven, plan-reviewed idle. It stops PostgreSQL and applies
`infrastructure/terraform/environments/idle.tfvars`, which **destroys the Enterprise Redis
and the Container Apps** while preserving the Premium container registry (ACR).

It is *not* the nightly job. `scripts/operator/azure-nightly-shutdown.sh`
(docs/NIGHTLY-AZURE-SHUTDOWN.md) is the cheap, fast-reversible power-down that runs on a
timer and never touches terraform. This one is the deep idle you run by hand when the
platform is going quiet for a while.

| | nightly shutdown | `azure-idle.sh stop` |
|---|---|---|
| trigger | scheduled, unattended | manual, interactive |
| Postgres | stopped | stopped |
| Container Apps | `--min-replicas 0` | **destroyed** |
| ACR | untouched | **preserved** (avoids image rebuild) |
| Redis | untouched | **destroyed** |
| images | keep | **kept** (ACR preserved) |
| terraform | never | plan + typed `yes` + apply |

---

## The command

```bash
scripts/operator/azure-idle.sh preflight   # read-only: prove every precondition
scripts/operator/azure-idle.sh stop        # idle  (plans, then waits for you to type 'yes')
scripts/operator/azure-idle.sh start       # resume ACR + Redis (plans, then waits for 'yes')
scripts/operator/azure-idle.sh status      # read-only inventory
scripts/operator/azure-idle.sh guard-plan plan.json   # read-only: the destroy guard alone
```

`stop` and `start` always print a full terraform plan and stop at:

```
  Type 'yes' to apply this plan:
```

There is deliberately no `--yes`, no `--auto-approve` and no environment variable that
skips it. That confirmation is the only local gate in front of a destroy of Redis and
the Container Apps.

> **In private mode these commands cannot actually reach Azure from your machine.** Key
> Vault is behind a private endpoint and the runner VM has no usable managed identity, so
> the real idle runs as a GitHub Actions job on the VNet runner — see
> [Running the idle from GitHub Actions](#running-the-idle-from-github-actions). That job
> uses two extra, non-interactive entry points, `plan-idle` and `apply-idle`, which are
> unreachable outside an Actions run and which move the typed confirmation into the
> workflow's own `confirm=IDLE` dispatch input rather than removing it.

### ACR is preserved — images remain available

`stop` preserves the Premium container registry. All images (operator-api, tracking-api,
worker, migration, ai-gateway, ai-llama) remain available, so the resume path is simply
to re-apply the workloads — no rebuild or re-push needed:

```bash
scripts/operator/deployment-preflight/dispatch-staging-workloads.sh
```

`azure-idle.sh start` brings back Redis and re-enables `deploy_workloads`, which
recreates the Container Apps pointing at the preserved images.

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
anything other than `yes`.** Since the workflow landed this is no longer only a matter of
reading carefully: the PostgreSQL server and database, the audit-anchor storage account /
container / immutability policy, and the CI runner VM are enforced by the machine-readable
destroy guard, which parses `terraform show -json` and refuses the apply outright. See
[the guard rails](#the-guard-rails).

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

So the deep idle must be run **from inside the VNet**, on the self-hosted CI runner VM.
Logging into that VM and running the command by hand does *not* work either: the VM has
**no usable managed identity** — `az login --identity` fails on it — so there is no
credential to run terraform with once you are there. The only credential that works on that
VM is **GitHub OIDC**, and OIDC is only issued to a GitHub Actions job.

VNet reachability *and* credentials together therefore exist in exactly one place: an
Actions job on the self-hosted runner. That is
[`.github/workflows/azure-idle.yml`](#running-the-idle-from-github-actions), below.

The preflight still refuses to continue from outside the VNet. `KP_INSIDE_VNET=1` is the
acknowledgement that you are already inside it, and the workflow sets it.

---

## Running the idle from GitHub Actions

`.github/workflows/azure-idle.yml` is the supported way to apply the idle posture. It is a
`workflow_dispatch`-only job that runs `scripts/operator/azure-idle.sh` on the
`["self-hosted","linux","azure-vnet"]` runner, authenticating with GitHub OIDC exactly the
way `.github/workflows/azure-deploy.yml` does (`ARM_USE_OIDC=true` plus `ARM_CLIENT_ID` /
`ARM_TENANT_ID` / `ARM_SUBSCRIPTION_ID` from the `staging` environment's variables — the
azurerm provider needs OIDC directly, not the `azure/login` service-principal session).
It sits behind `environment: staging`, so the required reviewer still has to approve it.

### The operator sequence

**The job cannot start the runner VM.** It executes *on* that VM, so the VM has to be
online before the job can be picked up at all; there is no earlier place to start it from.
Start it first, and deallocate it when you are done:

```bash
# 1. bring the runner online (it is deallocated by the nightly job)
az vm start -g rg-kp-staging -n vm-kp-staging-runner

# 2. plan — this is the default mode and changes nothing
gh workflow run azure-idle.yml -f mode=plan

# 3. read the full plan and the destroy summary in the run log, then apply
gh workflow run azure-idle.yml -f mode=apply -f confirm=IDLE

# 4. approve the `staging` environment review when GitHub asks

# 5. put the runner back to sleep
az vm deallocate -g rg-kp-staging -n vm-kp-staging-runner
```

The final step of the job prints steps 4 and 5 again, in the job summary, whether the run
succeeded or failed.

### The two dispatch inputs

| input | values | meaning |
|---|---|---|
| `mode` | `plan` (**default**) / `apply` | `plan` prints the full terraform plan and the destroy summary and stops. It does not even stop PostgreSQL. `apply` re-plans, guards, stops PostgreSQL and applies **that saved plan file** — never a bare re-resolution of the configuration. |
| `confirm` | must be exactly `IDLE` for `mode=apply` | The typed confirmation that replaces the interactive `yes`. It is checked three times: in a cheap `ubuntu-latest` job *before* the environment review is spent, again on the runner, and a third time inside `azure-idle.sh` (`require_dispatch_confirmation`). |

`mode=plan` needs no confirmation, because it changes nothing.

### The guard rails

**1. The destroy guard.** Every plan — from the workflow *and* from the interactive
`stop`/`start` — is rendered with `terraform show -json` and parsed structurally. The
rendered human plan is never grepped. The job **fails** (exit 3, nothing applied) if the
plan would delete or replace any of:

```
azurerm_postgresql_flexible_server.*          the data; idle STOPS the server, never removes it
azurerm_postgresql_flexible_server_database.* the data
azurerm_storage_account.audit_anchor          WORM / immutable, retained on purpose
azurerm_storage_container.audit_anchor
azurerm_storage_container_immutability_policy.audit_anchor
azurerm_linux_virtual_machine.ci_runner       the VM the job itself is running on
```

The guard is a separate, side-effect-free entry point, so it can be run over any saved
plan:

```bash
terraform show -json some.tfplan > plan.json
scripts/operator/azure-idle.sh guard-plan plan.json
```

It also prints the destroy/replace counts and names the two resources that are **not**
obviously "Container Apps + ACR + Redis" — the ACS delivery Event Grid system topic and the
custom ACS email-sender role definition/assignment. Both are gated on `deploy_workloads`,
neither holds data, and the next workloads deploy recreates them.

**2. The runner survives its own apply.** The workflow sets `KP_KEEP_CI_RUNNER=1`, which
makes `azure-idle.sh` add a CLI `-var=deploy_ci_runner=true`. `environments/idle.tfvars`
pins `deploy_ci_runner = false`, so without that override the apply destroys the VM
executing it, halfway through destroying everything else.

It has to be a **CLI `-var`**: a CLI `-var` outranks a `-var-file`, but a `TF_VAR_`
environment variable **loses** to one. `TF_VAR_deploy_ci_runner=true` would be silently
overridden by `idle.tfvars` — which is exactly the mistake that would take the runner out.

`terraform` additionally refuses `deploy_ci_runner=true` with an empty
`ci_runner_registration_token`, so the workflow passes the `CI_RUNNER_REGISTRATION_TOKEN`
environment secret (environment-scoped, not repository-scoped) and fails early with a named
message if it is missing. The VM's `lifecycle` ignores `custom_data`, so an expired token
cannot force it to be replaced; the value only has to exist.

**3. It cannot interleave with a deploy.** The workflow shares azure-deploy.yml's
`azure-staging` concurrency group, so whichever starts second queues.

### After an apply

* **The container registry is gone.** Every image is permanently deleted, digests included;
  rebuild and re-push with
  `scripts/operator/deployment-preflight/dispatch-staging-workloads.sh`.
* **Resume order: PostgreSQL first, then the apps.** The workloads fail their startup
  probes against a stopped database. `scripts/operator/azure-idle.sh start` does it in that
  order (it starts the server, then brings ACR + Redis back empty, and deliberately leaves
  `deploy_workloads=false`).
* **Deallocate the runner** — nothing does it for you on the apply path.

---

## RESOLVED: the first green plan proposed replacing the container app environment

**Run 34172986678 (2026-09-08) was the first `azure-idle.yml` run to plan successfully.** It
reported `1 to add, 0 to change, 23 to destroy` — and the single "add" was
`azurerm_container_app_environment.main` **being replaced**. That is the opposite of an idle
posture: recreating the environment changes `default_domain` and forces every container app to
be rebuilt on resume. The destroy guard printed `replace: 1` and **allowed it**.

Two independent defects, both fixed:

**1. The environment had undeclared, Azure-managed attributes.** Azure creates a Consumption
workload profile and a managed infrastructure resource group
(`ME_cae-kp-staging_rg-kp-staging_eastus2`) for every VNet-integrated environment, whether or not
the configuration asks. `main.tf` declared neither, which cost us twice:

- On the **deploy** path, every run refreshed them into state, saw config say `null`, and planned
  an in-place removal of the `workload_profile` block. Azure ignores the removal, so the identical
  no-op modify was planned and applied on every single run — twice within run 33970611034 alone.
  Permanent drift, and noise that hides real diffs.
- On the **idle** path, `infrastructure_resource_group_name` is ForceNew. Under `-refresh=false`
  the stale state value survives while config still says `null`, so terraform plans to replace the
  environment outright.

Fixed with `lifecycle { ignore_changes = [workload_profile, infrastructure_resource_group_name] }`.
`ignore_changes` rather than declaring the live values is deliberate — it cannot itself provoke a
replacement, whereas a hand-copied value that disagrees with the provider would, and there is no
way to plan-verify that from the controller.

**2. The guard did not protect the environment.** It is not count-gated on `deploy_workloads`:
idle *empties* it, it does not remove it. It is now in `PROTECTED_NAMED`, verified load-bearing by
replaying run 34172986678's exact plan shape through the guard (exit 3, refused) and a clean idle
plan (exit 0, allowed).

### Verified by the first refreshed plan — run 34175307493

Planned against a **running** PostgreSQL (so terraform refreshed from Azure rather than falling
back to state) on `4498ecb`:

```
Plan: 0 to add, 1 to change, 22 to destroy
destroy guard: create 0 / update 1 / replace 0 / DESTROY 22
guard OK — no protected resource is destroyed or replaced.
```

`replace: 0`. The environment is untouched, and the destroy set is exactly the documented
"Container Apps + Redis" (ACR preserved) plus the four ACS resources the guard flags as beyond it (system
topic, receipt subscription, role definition, role assignment — all gated on `deploy_workloads`
and recreated by the next workloads deploy).

**The `1 to change` was a third instance of the same drift**, surfaced only because this plan
refreshed. Azure populates
`actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]` on the
`Microsoft.App/environments` delegation of `snet-container-apps`; the configuration declared only
the delegation `name`, so every refreshed plan proposed removing an action that is intrinsic to
the delegation type. Now declared explicitly. Declared rather than ignored because `actions` is an
in-place attribute, not ForceNew — a wrong value fails an update instead of destroying a subnet,
which is why the environment's ForceNew attributes get `ignore_changes` and this one does not.

### `-refresh=false` plans are advisory, not authoritative

A stopped PostgreSQL rejects child-resource reads with `400 ServerStoppedError`, so `run_plan`
falls back to `-refresh=false` whenever the server is already `Stopped` — the state every re-run
after a nightly shutdown lands in. Such a plan is computed **from state, not from Azure**, so a
diff in it may be a stale-state artifact rather than real drift; the replacement above was exactly
that. The script now says so in its output. **Before believing any create/replace in an idle plan,
start PostgreSQL and re-plan.**

## RESOLVED blocker: redis-url was indexed unconditionally

**FIXED 2026-09-07 — `deploy_data_plane=false` now plans.** It was a configuration bug, not a
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
