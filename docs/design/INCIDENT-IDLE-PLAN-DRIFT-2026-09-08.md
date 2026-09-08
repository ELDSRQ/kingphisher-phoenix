# Incident: the idle plan proposed destroying the container app environment

**Date:** 2026-09-08
**Severity:** high (not triggered — caught at plan review)
**Detected by:** reading the first successful plan rather than trusting its exit code
**Commits:** `703a424`, `a56162d`
**Evidence:** workflow runs `34172986678` (unrefreshed, wrong) and `34175307493` (refreshed, correct)

## Summary

`azure-idle.yml` had never planned successfully. After four dispatch failures were fixed in
sequence, run **34172986678** finally went green. Its plan read:

```
Plan: 1 to add, 0 to change, 23 to destroy
  # azurerm_container_app_environment.main must be replaced
```

The single "add" was the **container app environment being destroyed and recreated**. Applying it
would have changed `default_domain` and forced every container app to be rebuilt — inside an
operation whose entire purpose is to scale things to nothing and leave them recoverable.

**The destroy guard printed `replace: 1` and allowed the plan through.**

Nothing was applied. The run was `mode=plan`, and the plan was read before anything else happened.

## Why this nearly landed

The green exit code was the trap. Four consecutive failures had trained attention onto "does it
run at all", and the run *succeeded* — validated inputs, planned, guarded, exited 0. Every
automated signal said the idle path was finally working. The defect was visible only in the body
of the plan, which is exactly the artifact a green check invites you to skip.

## Root causes

Three instances of one underlying class: **Azure populates attributes the configuration does not
declare, and terraform then plans to remove them.**

### 1. The environment's Azure-managed attributes (the dangerous one)

Azure creates a Consumption workload profile and a managed infrastructure resource group
(`ME_cae-kp-staging_rg-kp-staging_eastus2`) for every VNet-integrated environment, asked for or
not. `main.tf` declared neither. That cost us twice, and the two costs looked nothing alike:

- **On the deploy path** (refresh on): terraform refreshed the workload profile into state, saw
  config say `null`, and planned an in-place removal of the block. Azure ignores the removal, so
  the identical no-op modify was planned *and applied* on every single deploy — twice within run
  `33970611034` alone. Permanent drift; noise that hides real diffs.
- **On the idle path** (`-refresh=false`): `infrastructure_resource_group_name` is **ForceNew**.
  Without a refresh the stale state value survives against a `null` config, and terraform escalates
  from "update" to "replace the whole environment".

Same missing declaration. Cosmetic in one mode, destructive in the other.

### 2. The guard did not protect the environment

`PROTECTED_NAMED` covered PostgreSQL, the audit-anchor storage, the runner VM and the key vault.
The container app environment was absent — an understandable omission, since it is not count-gated
on `deploy_workloads` and idle *empties* it rather than removing it. Precisely because idle should
never touch it, a plan that proposes to is a bug worth stopping on.

### 3. The subnet delegation action

Found by the *refreshed* re-plan (`34175307493`) as a `1 to change`: Azure populates
`actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]` on the
`Microsoft.App/environments` delegation of `snet-container-apps`, the config declared only the
delegation `name`, so every refreshed plan proposed removing an action intrinsic to the delegation
type. Benign, but the same bug, and it had been running on every deploy for as long as the subnet
has existed.

## Fixes

| Cause | Fix | Commit |
|---|---|---|
| Environment's ForceNew attributes undeclared | `lifecycle { ignore_changes = [workload_profile, infrastructure_resource_group_name] }` | `703a424` |
| Guard did not protect the environment | added to `PROTECTED_NAMED` + `WHY` | `703a424` |
| `-refresh=false` plans read as authoritative | the script now labels them as computed from state, not Azure | `703a424` |
| Subnet delegation action undeclared | `actions = [...]` declared explicitly | `a56162d` |

### Why two different remedies for the same class of bug

Deliberate, and the asymmetry is the point:

- `workload_profile` / `infrastructure_resource_group_name` are **ForceNew**. A hand-copied value
  that disagrees with the provider destroys the environment. Terraform cannot be planned from the
  controller (the state backend sits behind a private endpoint), so that guess could not have been
  verified before it ran. `ignore_changes` **cannot itself provoke a replacement** — its failure
  mode is benign.
- `service_delegation.actions` is an **in-place** attribute. A wrong value fails an update; it does
  not destroy a subnet. Declaring it is safe, and it documents a real requirement.

Choose the remedy whose failure mode you can survive, not the one that reads best.

## Verification

**The guard fix is load-bearing** — replayed run 34172986678's exact plan shape through the
extracted guard:

- that shape → **exit 3, refused**, naming the environment
- a clean idle plan → **exit 0, allowed** (the guard did not simply become a brick)

**The terraform fix holds against a real refresh.** Re-planned with PostgreSQL `Ready`, so
terraform read Azure instead of falling back to state — run `34175307493` on `4498ecb`:

```
Plan: 0 to add, 1 to change, 22 to destroy
destroy guard: create 0 / update 1 / replace 0 / DESTROY 22
guard OK — no protected resource is destroyed or replaced.
```

`replace: 0`. The destroy set is exactly the documented "Container Apps + Redis" (ACR preserved) plus the
four ACS resources the guard flags as beyond it (system topic, receipt subscription, role
definition, role assignment — all `deploy_workloads`-gated and recreated by the next workloads
deploy).

## Lessons

1. **A green plan is an input to review, not a substitute for it.** The exit code said the tooling
   worked. It did. The plan was still wrong.
2. **`-refresh=false` produces plans that are advisory only.** They are computed from state, so a
   diff may be a stale-state artifact rather than real drift. The whole incident is one. It is now
   labelled in the script's own output.
3. **Undeclared Azure-managed attributes are not cosmetic.** The same omission was invisible
   drift-noise under refresh and a destroy-and-recreate without it. The per-deploy no-op modify was
   the early warning, and it had been firing on every run for weeks.
4. **A guard's protected set must include what the operation should never touch**, not only what it
   might plausibly delete. Everything guarded here was guarded because someone imagined losing it.
   Nobody imagined losing the environment, because idle never removes it — which is exactly why the
   proposal deserved a stop.
5. **Match the remedy's failure mode to what you can verify.** Both fixes are one line. One cannot
   be checked from this machine, so it got the remedy that cannot fail destructively.

## Related

- `docs/AZURE-IDLE.md` — the resolved-blocker sections carry the full detail
- `docs/design/AZURE-RESIDENCY-AUDIT-2026-09.md` — the ~$889/mo orphaned-replica leak, the
  `revision_mode = "Multiple"` defect from the same family of "the config did not say, so Azure
  decided"
