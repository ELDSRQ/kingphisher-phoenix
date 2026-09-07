# Nightly Azure shutdown — runbook

**Status:** implemented, **not yet enabled**. It does nothing until the operator
creates the GitHub Environment + federated credential below and sets one repo
variable. Written 2026-09-07.

**Scope:** this repo only.
Workflow: `.github/workflows/azure-nightly-shutdown.yml`
Script: `scripts/operator/azure-nightly-shutdown.sh`
Contract test: `tests/test_azure_nightly_shutdown_contract.py`

---

## Why this exists

Azure was ~$800/mo before the tier was idled. The expensive part is *always-on*
infrastructure, so the failure mode that costs real money is not a deliberate
deploy — it is **someone starting the stack for a test and forgetting to stop
it**. This job is the safety net for exactly that: at 23:00 the operator's local
time, if the compute tier is up, it goes back down.

Restart stays **manual and on demand**. There is deliberately no auto-start.

## What it is NOT — the distinction from `azure-idle.sh stop`

| | `azure-idle.sh stop` (unchanged) | this nightly job |
|---|---|---|
| Trigger | operator types it, reviews a plan, types `yes` | GitHub Actions `schedule:` |
| Postgres | stopped | stopped |
| Container Apps | **destroyed** (terraform `deploy_workloads=false`) | scaled to `min-replicas 0` |
| ACR (Premium) + Redis (Enterprise) | **destroyed** (`deploy_data_plane=false`) | **left intact** |
| CI runner VM | destroyed/absent | deallocated |
| Runs `terraform apply` | yes, interactively, plan reviewed | **never** |
| Reversal cost | full apply + re-push every image | `az` commands, or the next deploy |

`azure-idle.sh stop` is the deliberate, deeper, plan-reviewed idle and stays
exactly as it is. **The nightly job must never become that**: destroying the
container registry every night would force re-pushing every image before the
next morning's test, which directly defeats "restart when needed for testing and
pushing code", and an unattended `terraform apply` is precisely the thing that
should never run on a timer.

## What the nightly job stops

| Resource | Action | Why it is safe |
|---|---|---|
| PostgreSQL flexible server | `az postgres flexible-server stop` | Retains all data. Azure auto-restarts it after ~7 days. Biggest single cost lever (GP_Standard_D2ds_v5 compute). |
| Container Apps — `operator`, `tracking`, `ai-gateway`, every worker | `az containerapp update --min-replicas 0` | Removes the always-on replica charge. Terraform sets `min_replicas = 1`, so the next reviewed apply restores it; this is intentional drift, and reverting it *is* the restart. |
| CI runner VM (`vm-kp-staging-runner`) | `az vm deallocate` | Deallocated compute bills nothing; the OS disk survives, so `az vm start` brings the same registered runner back. |

Only resources tagged `application=kingphisher-phoenix` **and**
`environment=<the configured environment>` are touched. Anything else in the
resource group is skipped and logged with the reason.

## What it deliberately leaves running, and why

| Left up | Cost | Reason |
|---|---|---|
| **ACR (Premium)** and **Redis (Enterprise)** | the real Tier-2 cost after Postgres | Destroying them nightly means re-pushing every image the next morning. Removing them is a *deliberate* decision: `azure-idle.sh stop`, behind a reviewed terraform plan. |
| **ACS + verified email domain + public DNS + Event Grid + Entra** (Tier 1) | ~$0 (ACS is per-message) | The one part of a round trip that is painful to rebuild: SPF/DKIM re-verification, and the Namecheap "Email Forwarding purges records" trap. Never torn down. |
| Key Vault, audit-anchor Storage | small | The audit container is locked WORM by design; Postgres carries `prevent_destroy`. |
| Container Apps *environment*, networking | small in `starter` mode | Removed by terraform, never by a timer. |
| Container App **jobs** (migration) | $0 idle | Manually triggered; they cost nothing between runs. |

Caveat worth knowing: `operator` and `tracking` have HTTP ingress, so at
`min-replicas 0` an inbound request can still cold-start a replica. That is the
correct behaviour — you pay per request instead of paying 24/7 — but it means
"scaled to zero" is not "unreachable". If you want them genuinely unreachable,
that is `azure-idle.sh stop`.

## Daylight saving time — stated plainly

GitHub's `schedule:` cron is **UTC and has no DST handling**. 23:00
America/New_York is **03:00 UTC under EDT** and **04:00 UTC under EST**.

Both are scheduled:

```yaml
- cron: "0 3 * * *"   # 23:00 America/New_York while EDT (UTC-4)
- cron: "0 4 * * *"   # 23:00 America/New_York while EST (UTC-5)
```

and the first job **refuses to act unless the operator's local clock actually
reads hour 23** (`ZoneInfo("America/New_York")`, checked in the workflow, not
assumed from the cron). Exactly one of the two branches fires per night,
year-round; the other exits as a logged skip. There is **no seasonal drift**.

The window is one hour wide (23:00–23:59 local). GitHub delays scheduled runs
under load; a delay beyond 59 minutes means that night is **skipped**, logged as
`outside the 23:00 America/New_York window`, rather than firing at an unexpected
local hour. This is a safety net, not a hard guarantee.

## The four gates

A run only touches Azure if all four pass.

1. **Operator switch** — repo variable `NIGHTLY_AZURE_SHUTDOWN`:
   * unset / `disabled` → do nothing (**the default**; adding this workflow
     changes nothing until you arm it)
   * `dry_run` → run the full read-only what-if every night, change nothing
   * `enabled` → actually power down
   * anything else → refuse, and say so ("unreadable switch").
2. **Local-time window** — local hour must be 23 (skipped for a manual dispatch).
3. **Operator skip** — repo variable `NIGHTLY_AZURE_SHUTDOWN_SKIP_UNTIL`.
4. **No deployment in flight** — the job reads the run status of
   `azure-deploy.yml` and `provision-ci-runner.yml` and refuses while any run is
   `queued`, `in_progress`, `waiting`, `requested`, `pending` or
   `action_required`. It deliberately does **not** join their
   `azure-<environment>` concurrency group: queueing behind a deploy would make
   the power-down execute at an arbitrary later hour instead of skipping.

Every refusal is a **green run with a `::warning::`** and a step-summary table
naming which gate refused and why — not a red X, because "Azure was left running
tonight, on purpose" is a correct outcome, not a failure. A real failure (an `az`
call that errored) does exit non-zero.

If any of these cannot be evaluated — an unreadable switch, an unparseable skip
date, a GitHub API error — the job **fails safe by leaving Azure running**.

---

## Enabling it — exact operator steps

### Prerequisite: a decision you have to make

The existing deploy identity's variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID`) and its OIDC federated credential are scoped to the
**`staging` GitHub Environment, which requires a human reviewer**. That is
correct for a deploy and fatal for an unattended nightly job: it would sit
waiting for approval forever. So the nightly job needs its own GitHub
Environment with **no protection rules**, named `azure-nightly-shutdown`.

That environment must be able to authenticate to Azure. Two ways:

* **Option A (recommended, least privilege).** A separate Entra application with
  a custom role scoped to `rg-kp-staging` that can do only the three things.
  More setup; a compromised unprotected environment cannot then deploy or
  delete anything.
* **Option B (fast, wider blast radius).** Add one federated credential to the
  existing deploy application and copy its three variables. The deploy app holds
  **Contributor + User Access Administrator on the whole subscription**, so this
  makes subscription-wide rights reachable from an unprotected environment.

**Nothing below has been run.** Azure is idled and every live Azure action here
is operator-gated.

### Step 1 — create the unprotected GitHub Environment

```bash
gh api --method PUT repos/ELDSRQ/kingphisher-phoenix/environments/azure-nightly-shutdown
```

### Step 2A — least-privilege Azure identity (recommended)

> **Two things were learned running this for real on 2026-09-07:**
>
> 1. **You need BOTH federated-credential subject forms.** This repo has GitHub's
>    immutable-ID subject claims enabled, so Actions actually presents
>    `repo:ELDSRQ@172863608/kingphisher-phoenix@1321890015:environment:azure-nightly-shutdown`,
>    not the plain `repo:ELDSRQ/kingphisher-phoenix:...` form. Registering only the plain form
>    fails with `AADSTS700213: No matching federated identity record`. `kp-phoenix-deploy-staging`
>    already carries both, for the same reason. Create both (commands below).
> 2. **The role below is sufficient only because the script avoids
>    `az vm list --show-details`.** That flag shells out to network commands for IP addresses and
>    would additionally require `Microsoft.Network/networkInterfaces/read` and
>    `publicIPAddresses/read`. `azure-nightly-shutdown.sh` reads power state from the instance
>    view instead, and a contract test now asserts `--show-details` is never reintroduced.

```bash
SUBSCRIPTION="$(az account show --query id -o tsv)"
```

```bash
cat > /tmp/kp-nightly-shutdown-role.json <<JSON
{
  "Name": "KingPhisher nightly power-down",
  "IsCustom": true,
  "Description": "Back up then stop Postgres, scale Container Apps to zero, deallocate the CI runner. No delete.",
  "Actions": [
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.DBforPostgreSQL/flexibleServers/read",
    "Microsoft.DBforPostgreSQL/flexibleServers/stop/action",
    "Microsoft.DBforPostgreSQL/flexibleServers/backups/write",
    "Microsoft.App/containerApps/read",
    "Microsoft.App/containerApps/write",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/instanceView/read",
    "Microsoft.Compute/virtualMachines/deallocate/action"
  ],
  "NotActions": [],
  "AssignableScopes": ["/subscriptions/$SUBSCRIPTION/resourceGroups/rg-kp-staging"]
}
JSON
```

```bash
az role definition create --role-definition /tmp/kp-nightly-shutdown-role.json
```

```bash
az ad app create --display-name kp-phoenix-nightly-shutdown-staging
```

```bash
NIGHTLY_APP_ID="$(az ad app list --display-name kp-phoenix-nightly-shutdown-staging --query '[0].appId' -o tsv)"
az ad sp create --id "$NIGHTLY_APP_ID"
NIGHTLY_SP_OBJECT_ID="$(az ad sp show --id "$NIGHTLY_APP_ID" --query id -o tsv)"
```

```bash
az role assignment create \
  --assignee-object-id "$NIGHTLY_SP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "KingPhisher nightly power-down" \
  --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/rg-kp-staging"
```

```bash
az ad app federated-credential create --id "$NIGHTLY_APP_ID" --parameters '{
  "name": "azure-nightly-shutdown-environment-immutable",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:ELDSRQ@172863608/kingphisher-phoenix@1321890015:environment:azure-nightly-shutdown",
  "description": "Immutable-ID subject form GitHub actually presents",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

```bash
az ad app federated-credential create --id "$NIGHTLY_APP_ID" --parameters '{
  "name": "azure-nightly-shutdown-environment",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:ELDSRQ/kingphisher-phoenix:environment:azure-nightly-shutdown",
  "description": "Unattended nightly power-down from ELDSRQ/kingphisher-phoenix",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

```bash
gh variable set AZURE_CLIENT_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$NIGHTLY_APP_ID"
gh variable set AZURE_TENANT_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_SUBSCRIPTION_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$SUBSCRIPTION"
gh variable set NIGHTLY_AZURE_RESOURCE_GROUP --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "rg-kp-staging"
gh variable set NIGHTLY_AZURE_ENVIRONMENT_TAG --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "staging"
```

### Step 2B — reuse the deploy identity instead (faster, wider)

```bash
DEPLOY_APP_ID="$(az ad app list --display-name kp-phoenix-deploy-staging --query '[0].appId' -o tsv)"
az ad app federated-credential create --id "$DEPLOY_APP_ID" --parameters '{
  "name": "azure-nightly-shutdown-environment",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:ELDSRQ/kingphisher-phoenix:environment:azure-nightly-shutdown",
  "description": "Unattended nightly power-down from ELDSRQ/kingphisher-phoenix",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

```bash
gh variable set AZURE_CLIENT_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$DEPLOY_APP_ID"
gh variable set AZURE_TENANT_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$(az account show --query tenantId -o tsv)"
gh variable set AZURE_SUBSCRIPTION_ID --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "$(az account show --query id -o tsv)"
gh variable set NIGHTLY_AZURE_RESOURCE_GROUP --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "rg-kp-staging"
gh variable set NIGHTLY_AZURE_ENVIRONMENT_TAG --repo ELDSRQ/kingphisher-phoenix --env azure-nightly-shutdown --body "staging"
```

**No new repo *secret* is required by either option.** The workflow contains no
`secrets.` reference at all; Azure auth is OIDC, exactly like `azure-deploy.yml`.

### Step 3 — dry-run it manually first (do this before arming anything)

```bash
gh workflow run azure-nightly-shutdown.yml --repo ELDSRQ/kingphisher-phoenix -f dry_run=true
```

```bash
gh run list --repo ELDSRQ/kingphisher-phoenix --workflow azure-nightly-shutdown.yml --limit 1
```

Read the run summary. It must list every project resource, print
`would run: az ...` for each intended action, and change nothing. `dry_run`
defaults to `true`, so a bare `gh workflow run azure-nightly-shutdown.yml` is
also safe.

You can run the same what-if from your own machine with your own `az` login:

```bash
az login
```

```bash
bash scripts/operator/azure-nightly-shutdown.sh --dry-run --json
```

### Step 4 — arm the schedule in read-only mode for a night or two

```bash
gh variable set NIGHTLY_AZURE_SHUTDOWN --repo ELDSRQ/kingphisher-phoenix --body dry_run
```

Check the next morning that exactly one of the two nightly runs entered the
window and that its what-if names the resources you expect.

### Step 5 — arm it for real

```bash
gh variable set NIGHTLY_AZURE_SHUTDOWN --repo ELDSRQ/kingphisher-phoenix --body enabled
```

### Turning it off again

```bash
gh variable set NIGHTLY_AZURE_SHUTDOWN --repo ELDSRQ/kingphisher-phoenix --body disabled
```

---

## Skipping a night (long test running, overnight soak, real send in progress)

Set an expiry, not a flag — it turns itself back on, so a skip cannot silently
become permanent.

Skip tonight only (a bare date means "through the end of that local day"):

```bash
gh variable set NIGHTLY_AZURE_SHUTDOWN_SKIP_UNTIL --repo ELDSRQ/kingphisher-phoenix --body 2026-09-08
```

Skip until a precise local time:

```bash
gh variable set NIGHTLY_AZURE_SHUTDOWN_SKIP_UNTIL --repo ELDSRQ/kingphisher-phoenix --body 2026-09-09T06:00:00-04:00
```

Cancel the skip early:

```bash
gh variable delete NIGHTLY_AZURE_SHUTDOWN_SKIP_UNTIL --repo ELDSRQ/kingphisher-phoenix
```

An unparseable value is treated as "skip tonight" with a loud warning, never as
"go ahead".

You do **not** need to set this for a deploy: an in-flight `azure-deploy.yml` or
`provision-ci-runner.yml` run already blocks the power-down automatically.

---

## Restarting on demand (there is no auto-start)

Check what is actually down first:

```bash
bash scripts/operator/azure-idle.sh status
```

**1. Postgres** (a few minutes to become `Ready`):

```bash
az postgres flexible-server start -g rg-kp-staging -n "$(az postgres flexible-server list -g rg-kp-staging --query '[0].name' -o tsv)"
```

**2. Container Apps.** The reviewed path is a normal deploy — terraform declares
`min_replicas = 1`, so applying restores it and undoes the nightly drift. For a
quick manual bring-up without a deploy:

```bash
for app in $(az containerapp list -g rg-kp-staging --query "[].name" -o tsv); do
  az containerapp update -n "$app" -g rg-kp-staging --min-replicas 1
done
```

**3. CI runner VM** (only needed for a `private`-mode deploy):

```bash
az vm start -g rg-kp-staging -n vm-kp-staging-runner
```

**4. Operator console OIDC.** The `OPERATOR_API_OIDC_*` env re-patch only reverts
on a *deploy*; scaling replicas back up does not disturb it. If you did deploy,
re-patch it — `scripts/operator/azure-idle.sh start` does this step for you.

If instead the deeper `azure-idle.sh stop` was used (ACR/Redis destroyed), the
restart is `scripts/operator/azure-idle.sh start`, not the commands above.

---

## Reading the log

Every run writes a step summary with a decision table, the full script output,
and (in the `--json` action log) one record per resource:

```json
{"action":"scale_to_zero","kind":"containerapp","name":"ca-kp-staging-operator","reason":"min-replicas was 1","result":"scaled_to_zero"}
{"action":"none","kind":"postgres","name":"psql-kp-staging","reason":"state is Stopped, not Ready","result":"skipped"}
```

The same log is uploaded as the `nightly-azure-shutdown-<run>-<attempt>`
artifact for 30 days.

## Safety properties, and how they are tested

`tests/test_azure_nightly_shutdown_contract.py` pins all of this offline,
against an `az` shim and by executing the workflow's own embedded decision
programs:

* the script issues exactly four writes for a fully-running stack and never
  reads or touches ACR, Redis, ACS, DNS, Event Grid, Key Vault or storage;
* `--dry-run` issues **no** Azure write;
* already-stopped / already-zeroed / already-deallocated resources are logged
  skips with `changed: 0`, not errors;
* untagged or wrong-environment resources are skipped with a reason;
* the source contains no `terraform`, no delete/destroy/purge, and no `start`;
* a mutating command outside the three-entry allowlist is refused before it
  reaches Azure;
* the 23:00 window fires exactly once per night in both EDT and EST;
* `disabled`, an unreadable switch, an active skip, an unparseable skip date, a
  deploy in flight, and an unreadable GitHub API all leave Azure running;
* every `uses:` is pinned to a full commit SHA and no job holds a `write`
  permission other than `id-token`.
