# AI Handoff — 2026-09-19

Canonical current-state handoff. Supersedes `AI_HANDOFF_2026-09-17.md`. The
project’s auto-memory (loaded each session) holds fine-grained detail; this doc
is the self-contained map. Copy-ready resume prompt: `NEXT_AI_PROMPT.md`.

## Azure staging is DEPLOYED — 2026-09-20

All three phases are green and verified against the live control plane.
`main` at `5341c35`, CI green, zero open PRs. PRs #42-#52 landed this session.
Azure is POWERED DOWN after the deploy (see Cost posture below) — bring it
back up before any Azure work.

| | |
| --- | --- |
| Container apps | `operator`, `tracking`, `worker`, `ai-gateway` — Running |
| Migration | `caj-kp-staging-migration`; migrate-and-qualify passed |
| ACS domain | Domain, SPF, DKIM, DKIM2 — **all Verified** |
| Sender | `awareness@mail.floridamanevolved.us` bound; domain associated |
| Private endpoints | 5 — acr, vault, postgres, redis, audit-anchor |
| Receipts | ACS Event Grid subscription activated and verified |
| Operator console | `https://ca-kp-staging-operator.jollybeach-1b54592b.eastus2.azurecontainerapps.io` |

**Network mode is now `private`, not `starter`.** The runner is therefore the
self-hosted `azure-vnet` VM (`vm-kp-staging-runner`), selected automatically by
`azure-deploy.yml:340` from `network_mode`.

### Non-obvious things this took — read before touching the deploy

1. **`foundation_bootstrap` cannot be re-run after `foundation_finalize`.** The
   bootstrap stage sets the ACS association and sender username to count 0, and
   both carry `prevent_destroy` (`main.tf:580`, `:595`), so the plan aborts
   before the allowlist. Verified by run `35531923482`.
2. **`foundation_finalize` is `-target`ed** at exactly those two ACS resources,
   so it plans nothing else — it cannot converge foundation networking. A
   finalize that reports `0 added, 0 changed, 0 destroyed` is doing its job, not
   skipping work.
3. **Only `workloads` plans the full config.** That is why the starter->private
   migration had to complete through the workloads phase, and why its supply
   chain must work while the transition is incomplete (#49).
4. **The Foundry account is NOT Terraform-managed.** `ais-kp-staging-6117w` died
   with the 2026-09-14 teardown and had to be recreated out of band before
   `azurerm_role_assignment.ai_gateway_foundry_user` could apply. Recreate with
   `scripts/operator/deployment-preflight/recreate-foundry-and-finish.sh`.
   Model formats differ: the GA models are `OpenAI`, the open-weight gpt-oss
   family is `OpenAI-OSS`. Check with `az cognitiveservices model list -l eastus2`.
5. **The operator has no Key Vault data-plane role.** Only the deploy SP
   (`867a1a69-...`) holds Key Vault Secrets Officer on `kvkpstaging6117w`.
   Subscription Owner does not grant data-plane access on an RBAC-model vault,
   so `az keyvault secret ...` fails with Forbidden until an explicit grant is
   made (and RBAC propagation needs ~2 minutes, not seconds).
6. **A failed apply can orphan a Key Vault secret** — created in Azure, absent
   from state, so the next apply fails with "a resource with the ID ... already
   exists". Clear it by deleting AND purging the secret (soft-delete is on,
   purge protection is off), then re-running.

### Fixes landed this session

- **#42/#44** stale-state repair script, then the fix for its vacuous guard: it
  keyed on `id-kp-staging-6117w-worker`, a name that never existed (the suffix
  is `kp-staging`), so it protected nothing and would have removed a healthy
  entry. It now proves staleness per address.
- **#43/#45** ai-gateway bearer gating. #43 alone was a **no-op**: neither
  foundation plan step passed `deploy_ai_gateway`, so it defaulted to `false`
  and the count was 0 either way. #45 passes it in both foundation plan steps.
- **#47** restore the ACR posture the network mode declares, not a blanket
  `Disabled` — starter mode is public by design and a blanket close locked out
  the runner and the Container App image pulls.
- **#49** keep the registry window open across the whole supply chain (scan
  pulls, attest pushes, verify pulls) instead of closing it right after the
  build. Closing early only works when a private endpoint already exists.
- **#46/#50** docs: corrected bootstrap guidance; retired the `.140` references.

> **Do NOT run `repair-stale-bootstrap-state.sh` routinely.** With #43/#45 the
> ai-gateway pair can no longer collapse, and the script detects that and skips
> it. It remains valid only for DRIFT — a role assignment orphaned because its
> identity was deleted outside Terraform. Against healthy state it would remove
> live resources and make the next plan create duplicates.

### Dispatching

```bash
bash scripts/operator/deployment-preflight/dispatch-staging-bootstrap.sh
NETWORK_MODE=private PHASE=foundation_finalize bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh
NETWORK_MODE=private PHASE=workloads bash scripts/operator/deployment-preflight/dispatch-staging-finalize.sh
```

`scripts/operator/deployment-preflight/recreate-foundry-and-finish.sh` does
Foundry-recreate + dispatch + approve + follow in one command.

Approval needs the quoted, typed form — `-f` sends a string and zsh globs `[]`:

```bash
gh api --method POST /repos/ELDSRQ/kingphisher-phoenix/actions/runs/RUN_ID/pending_deployments -F 'environment_ids[]=20961255392' -f state=approved -f comment='...'
```

### Cost posture

Azure was powered down after this deploy with
`scripts/operator/azure-nightly-shutdown.sh` (Postgres stopped, Container Apps
to `min-replicas 0`, runner VM deallocated) — reversible, and it keeps ACR and
Redis so the next run needs no rebuild. `azure-idle.sh stop` is the deeper,
cheaper idle that additionally destroys ACR and Redis; it forces a full image
rebuild on resume.

### Still open on Azure

- **Second-identity approver is not provisioned.** Pattern self-approval is
  barred unconditionally, so a solo operator cannot complete a campaign. Use
  `licensing@` (`AZURE_CONFIG_DIR="$HOME/.azure-licensing"`).
- **#45 is still behaviourally unproven for the recurrence it fixes.** Its real
  test is the next `foundation_bootstrap` after a workloads deploy — the first
  time the ai-gateway secret exists in state and must survive rather than be
  destroyed. Note (1) above: that bootstrap cannot run on this environment now.
- **Starter mode `workloads` has never completed.** Beyond #47/#49, the
  `actions/attest` steps fail on a GitHub-hosted runner with
  "No credentials found for registry" despite a valid `DOCKER_CONFIG`; the
  action's own example uses `docker/login-action`. Unresolved, and only matters
  if starter-mode workloads is wanted.
- A campaign has **not** been run end to end on Azure.

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

> **B1 boot persistence: DONE 2026-09-20.** `kp-aggregate` is `active` under
> WSL systemd (it was previously a hand-started `llama-server` outside systemd,
> so nothing would have restarted it), and the `KP-Aggregate-Model` logon task
> starts that unit. Verified by a full WSL shutdown/restart cycle: the unit
> brought `qwen3-30b-a3b-aggregate` back by itself. Use
> `scripts/operator/alice-boot-persistence.sh`, which SSHes to Alice and checks
> every precondition before creating anything.
>
> **Do NOT try WSL2 mirrored networking to expose the model on the LAN.** It was
> tried and reverted on 2026-09-20. It does not work here: mirrored mode gives
> WSL the host's own IP, so inbound LAN traffic is answered by the Windows stack
> which has no listener and sends RST ("connection refused"). Neither a per-port
> Hyper-V rule nor `DefaultInboundAction=Allow` changed that. It also REGRESSES
> the Windows `127.0.0.1:18082` -> WSL forwarding that default NAT mode provides
> for free (that needs `hostAddressLoopback=true` under mirrored mode).
>
> **The LAN gap is probably not a gap.** `model_control.py:39` defaults
> `KP_MODEL_CONTROL_LLAMA_URL` to `http://127.0.0.1:18082`, i.e. the platform
> expects the model on localhost. Either run the operator API on Alice, or use
> an SSH tunnel as the handoffs already do for other Alice services:
>
> ```bash
> ssh -N -o IdentitiesOnly=yes -i ~/.ssh/alice_dr_ed25519 -L 18082:127.0.0.1:18082 erikd@192.168.1.36
> ```
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
Operator directive 2026-09-20: **on-prem human-ready first, then Azure;
deprioritize additional layered-security work.**

**On-prem (P0)**
1. ~~DOC-030 — docs pointed at the retired `.140` worker~~ DONE (PR #50).
2. **B1 — Windows boot persistence on Alice** (operator, classifier-blocked):
   `schtasks /Create /TN "KP-Aggregate-Model" /TR "wsl.exe -d Ubuntu-24.04 -u root -e systemctl start kp-aggregate" /SC ONLOGON /RL HIGHEST /F`
   Without it a reboot silently drops the A3B model and aggregation dies unsignalled.
3. **On-prem human-acceptance dry run** — a non-technical operator drives a full
   campaign lifecycle unassisted. This is the definition of ready; the rest is proxy.

**Azure (P1)**
4. ~~C2 — Azure end-to-end~~ DONE 2026-09-20; see the deployment section above.
5. **Second-identity approver not provisioned** — pattern self-approval is barred
   unconditionally, so a solo operator cannot complete a campaign. `licensing@`
   with `AZURE_CONFIG_DIR="$HOME/.azure-licensing"`.
6. **Azure campaign dry run** — never yet run end to end.

**DEP-010 and MAIL-005 are COMPLETE** — both landed 2026-09-13
(`AI_HANDOFF_2026-09-13.md`, PRs #7 and #9). Do not re-do them.

> **Caution on "complete" claims.** That same handoff also recorded DOC-030 as
> done on 2026-09-13, yet 38 references to the retired `.140` worker were still
> live in 16 markdown files on 2026-09-20 — including `README.md`, `RUNBOOK.md`
> and `AGENTS.md` — and `docs/WAVE-BUILD-PLAN.md` still named it under a
> "Current engineering topology" heading. DOC-030 was finally closed by PR #50.
> Verify a completion claim against live code or live docs before trusting it.

**Production/RSA NO-GO stands** until the full-suite, exact-final-image, native
AMD64/registry, browser/WCAG, cloud/provider, recovery, and human-acceptance
gates are proven. Nothing in this session changes that.


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
