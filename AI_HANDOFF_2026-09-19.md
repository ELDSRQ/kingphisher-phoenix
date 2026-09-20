# AI Handoff — 2026-09-19

Canonical current-state handoff. Supersedes `AI_HANDOFF_2026-09-17.md`. The
project’s auto-memory (loaded each session) holds fine-grained detail; this doc
is the self-contained map. Copy-ready resume prompt: `NEXT_AI_PROMPT.md`.

## Live Azure continuation — 2026-09-20

`main` is at `44ce5d8` (PR #41, merged with required CI green). The
stale-Terraform-ACS repair is live. Three blockers were cleared in sequence
this session; each is recorded below because the failure modes recur on every
rebootstrap of a torn-down environment.

**1. Key Vault deployer binding (run `35515025480`).** The recovered Key Vault
was missing the exact Terraform-managed deployer binding. Restored in Azure
without state surgery:

- principal: `kp-phoenix-deploy-staging` (`9407ae13-324a-4f7d-bb3c-08f4ce0d3365`)
- role: `Key Vault Secrets Officer`
- assignment: `5186c3e9-46e8-bd62-fc99-5063549086ba`
- scope: vault `kvkpstaging6117w` in `rg-kp-staging`

**2. Stopped PostgreSQL (run `35515814350`).** The plan failed with
`ServerStoppedError` reading the `kingphisher` database and the
`azure.extensions` configuration. `psql-kp-staging-6117w` was started and reads
`Ready`.

**3. Stale state vs. the create/update-only allowlist (runs `35515814350`,
`35516897770`).** With Postgres up, the plan was
`62 to add, 3 to change, 3 to destroy` — and the step "Enforce ACS foundation
bootstrap plan allowlist" (`.github/workflows/azure-deploy.yml:1429`) refuses
*any* delete or replacement outside an explicit ACS domain rotation. All three
were stale, not real:

| Address | Action | Cause |
| --- | --- | --- |
| `random_password.ai_gateway_auth[0]` | destroy | `count = var.deploy_workloads && var.deploy_ai_gateway` (`main.tf:759`); `foundation_bootstrap` hardcodes `deploy_workloads=false` (`azure-deploy.yml:1427`) so the count collapses to 0. No Azure resource backs it. |
| `azurerm_key_vault_secret.runtime["ai-gateway-auth-key"]` | destroy | reads `random_password.ai_gateway_auth[0].result` (`main.tf:1119`); falls with it. |
| `azurerm_role_assignment.audit_anchor_writer` | replace | binds `azurerm_user_assigned_identity.workload["worker"].principal_id` (`main.tf:941`); that identity no longer exists, so `principal_id` became known-after-apply and forced replacement. The live assignment `e663f127-2265-96eb-fcf9-52ffe53b67f8` was orphaned to deleted principal `dc6b022c-b298-4700-a90f-645db8b6a68a`. |

Repaired by `scripts/operator/deployment-preflight/repair-stale-bootstrap-state.sh`
(new, untracked). It snapshots state, re-verifies the worker identity is really
absent, removes exactly those three addresses, deletes orphaned assignments
whose principal no longer resolves, and verifies. It is read-only unless run
with `CONFIRM=yes`. State went from serial 247 to 175 resources remaining;
rollback snapshot:
`.tf-state-snapshots/staging-kingphisher-20260920T144428Z.tfstate`.

**How this was actually fixed (read before running the repair script).** The
conflict had two independent halves, fixed in three PRs:

- **#43** changed `random_password.ai_gateway_auth` (`main.tf:768`) to gate on
  `deploy_ai_gateway` alone instead of `deploy_workloads && deploy_ai_gateway`,
  with the Key Vault entry and both grants on it moved to match.
- **#45** was needed because #43 alone did nothing: neither foundation plan
  step passed `deploy_ai_gateway`, `staging.tfvars` does not set it, and it is
  not among the 38 reviewed config keys, so it fell back to its declared
  default of `false` and the count was 0 either way. #45 passes it in both the
  bootstrap and finalize plan steps, as the workloads and receipt plans already
  did. Both were required: fixing only bootstrap would have moved the destroy
  into finalize and tripped that phase's allowlist instead.
- **#44** fixed the repair script itself, which guarded on a hardcoded identity
  name (`id-kp-staging-6117w-worker`) that never existed — the suffix is
  `kp-staging` — so the guard passed vacuously. It now proves staleness per
  address and leaves healthy entries alone.

> **Do NOT run the repair script as a routine pre-dispatch step.** With #43 and
> #45 in, the ai-gateway pair can no longer collapse under
> `foundation_bootstrap`, and the script detects this and skips them. What it
> still legitimately handles is *drift*: a role assignment orphaned because its
> identity was deleted outside Terraform. That is not self-inflicted by the
> phase and is not always present. Run it read-only to diagnose a plan that
> shows destroys; run it with `CONFIRM=yes` only when it proves an address
> stale. Running it against healthy state would remove live resources from
> state and make the next plan create duplicates.

**Runs.** `35517495114` was the first green `foundation_bootstrap` (after the
manual state repair). `35520770863` then re-ran it on fixed `main` with no
repair step: `Apply complete! Resources: 0 added, 0 changed, 0 destroyed`. Note
that this run did **not** prove #43 worked — state was already clean; the
`0 added` is the tell that the secret was still not being created. Superseded:
`35516897770` (cancelled), `35515814350`, `35515025480`.

To dispatch a phase:

```bash
bash scripts/operator/deployment-preflight/dispatch-staging-bootstrap.sh
bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh
PHASE=workloads bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh
gh api /repos/ELDSRQ/kingphisher-phoenix/actions/runs/RUN_ID/pending_deployments
```

The success signal at the allowlist is **`0 to destroy`**. The gate runs before
`terraform apply`, so a dirty plan costs time but mutates nothing — it is always
safe to approve and let the gate answer.

**Still unproven:** #45's behavioural test is the first `foundation_bootstrap`
run *after* a workloads deploy, i.e. the first time the ai-gateway secret exists
in state and must survive the phase rather than be destroyed. Until that run
happens, treat the recurrence as fixed-in-theory only.

Then continue `foundation_bootstrap → foundation_finalize → workloads`. Do not
claim C2 complete until Terraform evidence, ACS DNS records, domain/SPF/DKIM/
DKIM2 verification, workloads, browser/WCAG, recovery, and human-acceptance
gates all pass. Production/RSA remains NO-GO.

The preserved Terraform state blob was snapshotted before the ACS repair at
`2026-09-20T13:20:53.0397783Z`. No *broad* state surgery was performed: the only
state modification was the three-address removal described above, each verified
stale against live Azure first, with a full local snapshot taken before the
change. Current worktree user-owned uncommitted files are the handoff docs,
`.hermes/`, `scripts/operator/merge-open-prs.sh`, and the new
`scripts/operator/deployment-preflight/repair-stale-bootstrap-state.sh`;
`.tf-state-snapshots/` is gitignored via `*.tfstate`. Do not `git add -A`.

---

## What this product is
`phishing-awareness-platform` (repo `ELDSRQ/kingphisher-phoenix`, working dir
`/Users/edierks/projects/codex-test/phishing-awareness-platform`) — a GUI-driven
phishing-**awareness training** platform. Safe simulations only; no real
credential capture. Dual-deployment, first-class both ways: **on-prem** and
**Azure**.

## Standing scope constraints (do not violate)
- **Work only on this repo.** A separate agent owns CROW (`~/crow`) + the DR
  mechanism (dr-sync, launchd `com.kingphisher.dr-sync`, `~/bin`) — do NOT touch
  those. The hardware (Alice `192.168.1.36` RTX 3090; Strix Halo `192.168.1.24`)
  is the operator's and in scope for model hosting when directed.
- **Classifier blocks (system-level):** PR merges, credential/SSH *setup*,
  Windows/mac boot-persistence creation (schtasks / launchd load). Operator runs
  those; you provide commands. Using an existing SSH connection is fine.
- **Never merge PRs with `--admin`; wait for required CI gates.**
- **Docker builds only on `.105`**; the Mac has no daemon.
- **Second-identity approval is unconditionally barred for self.**
- **AZURE_CONFIG_DIR:** infra ops need `export AZURE_CONFIG_DIR="$HOME/.azure"`;
  `KP_DISABLE_DOTENV=1` for test suites.
- **Every PR:** repo-wide `ruff check . && ruff format --check .` + typecheck;
  UI PRs also need the console suite (`test_console_non_azure_wiring_contract`,
  `test_console_bundle_drift` + `npm run build`).
- **Attribution:** commits end with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` +
  `Claude-Session: https://claude.ai/code/session_01FqPVAcrzBBuiAbNmtJryUF`.

## What was merged this session (2026-09-18 → 2026-09-19, all on `main`, CI green)
The human-readiness workstreams, end to end:

- **#32** aggregation-quality eval cases + deterministic runner
  (`scripts/ai-bakeoff/aggregation_evaluation_set.yaml` +
  `aggregate_evaluate.py`) + ACS DNS click-to-copy in the deployment wizard
  (re-pinned `azure-deploy.yml` digest in `deployment_common.py`).
- **#33** **Qwen3-30B-A3B** made the permanent on-prem aggregation model
  (`scripts/operator/ai-model-swap.sh`, `model_control.py` label).
- **#34** one-time first-run console password (`POST /api/v1/console/password`,
  12+ chars letter+digit, fail-closed once set, never logged/audited).
- **#39** (was #35) aggregation eval hardening: set v1.1, 3→6 discriminating
  cases (value-over-recency, near-tie recency, stale-twin disambiguation).
- **#36** unattended periodic aggregation (`AggregationScheduler` in
  `aggregation_routes.py`; opt-in, off by default, fail-closed, **never
  auto-promotes** — candidates only, human promote gate unchanged).
- **#37** ciphertext active-key id pre-filled with its reviewed default
  (`primary`) in the deployment wizard (A3).
- **#38** Entra app-list discovery by friendly name (A2b) — a second opt-in
  "Discover Entra apps" step using delegated `Application.Read.All` against
  `graph.microsoft.com/v1.0/applications`; token stays in-browser, never
  persisted; CSP `connect-src` gained `https://graph.microsoft.com`.
- **#25** docs canonical-handoff pointer.

Verified on merged main: full hermetic suite green (3318 passed), ruff + format
clean, strict mypy clean (46 files), console bundle drift clean.

## On-prem is LIVE on Alice (192.168.1.36) — the operator's RTX 3090
Reached via `ssh alice` (config alias, key `~/.ssh/alice_dr_ed25519`, user
`erikd`). Windows 11 + WSL2 Ubuntu-24.04 (home `/root`, runs as root).

- **Aggregation model: Qwen3-30B-A3B-Instruct-2507-Q4_K_M** (30.5B total /
  3.3B active, MoE). Served by llama.cpp on `0.0.0.0:18082`, OpenAI-compatible +
  json_schema, ~19.6 GB resident, all 48 layers on GPU (flags `-c 32768 -fa on
  -ctk q8_0 -ctv q8_0 -ngl 99`). Alias `qwen3-30b-a3b-aggregate`. Eval: **6/6**
  on the hardened v1.1 set (~6.2s/case). GGUF at
  `/opt/kp-ai010/qwen3-30b-a3b/Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf`.
- **qwen3:32b is UNLOADED from Ollama** (it was the Scribe/swap model; only
  restored via console swap). gpt-oss-20b is retired as the aggregation model.
- **App stack:** supervisor (operator-api :8000, tracking-api :8001, 9 workers)
  + ai-gateway `:8090`, all pointed at `:18082`. Console at
  `http://127.0.0.1:8000/console`; Mac tunnel → `http://127.0.0.1:8800/console`.
- **Reboot persistence:** model via WSL systemd `kp-aggregate.service`
  (`enabled`). **Windows schtasks `KP-Aggregate-Model` is DELETED** — operator
  must recreate it (command in "Remaining tasks"). App-stack boot task
  (`KP-App-Stack`) still not registered.

## Azure (cost-minimized, nothing critical deleted)
`rg-kp-staging` is trimmed to the floor **non-destructively** (Postgres is now
`Ready` for the active C2 retry; stop it again only after evidence is captured),
NAT/pip/private-endpoint deleted 2026-09-17, all Terraform-defined + recreated by
the GUI wizard). Terraform state `rg-kp-tfstate-staging` untouched. The DEP-010
GUI wizard drives `terraform apply` via `.github/workflows/azure-deploy.yml`
(digest-pinned `90473530bc5f…a5b3c`). Other RGs (`raven-*`, `atprod*`) are OTHER
projects — never touch.

## Remaining tasks / gates
1. **C2 — Azure end-to-end integration run (in progress):** bootstrap must be
   rerun with PostgreSQL `Ready`, then `foundation_finalize → workloads` must
   complete. Capture the four DNS records and configure them at the external DNS
   provider; do not claim domain/SPF/DKIM/DKIM2 readiness before Azure readback.
2. **Windows schtasks (operator, classifier-blocked):**
   `schtasks /Create /TN "KP-Aggregate-Model" /TR "wsl.exe -d Ubuntu-24.04 -e bash -lc /root/kp-aggregate-start.sh" /SC ONLOGON /RL HIGHEST /F`
3. **Production/RSA NO-GO stands** until the full-suite, exact-final-image,
   native AMD64/registry, browser/WCAG, cloud/provider, recovery, and
   human-acceptance gates are proven. Nothing in this session changes that.

## Known issues fixed this session
- **Stale workflow-digest pin:** `tests/test_azure_idle_workflow_contract.py`
  still pinned the pre-DNS `azure-deploy.yml` digest (`ac414dc…`) after #32
  changed it; the hermetic CI gate failed on #32/#35. Re-pinned to
  `6d7535484aa2…40e7` (verified against the file).
- **Branch-hygiene:** several feature branches had chained bases (each carried
  earlier PRs' commits); rebased all onto `origin/main` so each PR is
  self-contained. The `merge-open-prs.sh` script still uses `--delete-branch`,
  which auto-closed the dependent #35 when #32's base branch was deleted — #35
  was recreated as #39. If reusing the script on dependent PRs, drop
  `--delete-branch` or retarget the dependent first.
- **Stale ACS Terraform state:** PR #41 (`44ce5d8`) now treats a completely
  absent live ACS parent pair as pending only during `foundation_bootstrap`;
  partial, divergent, malformed, finalize, and workload states remain
  fail-closed. Its reviewed workflow digest is `90473530bc5f…a5b3c`.
- **Recovered Azure RBAC / idle database:** the exact missing Key Vault
  `Key Vault Secrets Officer` assignment was restored for the deployment
  principal. The first retry then proved the next blocker was the intentionally
  stopped PostgreSQL server; it is currently `Ready` for the next bootstrap.

## Fast health check
`ssh alice "wsl -d Ubuntu-24.04 -e bash -lc \"curl -sf http://127.0.0.1:8000/readyz; curl -sf http://127.0.0.1:8090/livez; curl -sf http://127.0.0.1:18082/health\""`
