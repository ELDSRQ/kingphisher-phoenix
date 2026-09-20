# Human-Ready Readiness Plan — Kingphisher-Phoenix

> **For Hermes:** Planning only — this turn produces no code. Each numbered workstream ships as its own PR, merged by the operator after CI. Repo-wide `ruff check . && ruff format --check .` before every PR, plus the console suite (`test_console_non_azure_wiring_contract`, `test_console_bundle_drift`, `test_ux011_console_wiring_contract` + `npm run build`) before any UI PR. Docker builds only on the `.105` WSL2 worker.

**Goal:** A non-technical human security analyst can deploy, configure, and operate the platform end-to-end on BOTH the on-prem and Azure paths, with every remaining gap closed and proven by build + validation — not just by code review.

**Current state (done, merged or in review):**
- Console humanization WS1–WS3: raw IDs/hashes collapsed behind "Advanced", friendly names as labels (PRs #26–#28).
- WS5/WS6: help glossary + `docs/OPERATOR-GUIDE.md` + first-class deployment chooser (PR #29).
- AI model residency control in the console (PR #31) and the permanent model swap to Qwen3-30B-A3B, deployed and live on Alice (PR #33).
- Aggregation-quality eval harness + cases (PR #32) and ACS DNS click-to-copy (PR #32) — code done, Azure path untested live.

**What "human ready" still requires** is four categories: (A) two console gaps, (B) two on-prem operational gaps, (C) two validation gaps, (D) the production/acceptance gates that are the standing NO-GO from AGENTS.md.

---

## A. Remaining console humanization

### A1 — First-run credential UX (WS4, not yet built)

**Objective:** Remove the "read a random `KP_CONSOLE_PASSWORD` from `.env`" step. A status probe already reports `console_password_set` (`runtime_status.py:94`); the actual one-time set/reset flow is missing.

**Build:**
- `apps/operator-api/src/kp_operator_api/console/env_store.py` — add a guarded `set_console_password()` write (min-length + complexity, never logged, never in audit) reusing the existing `.env` atomic-write path.
- `apps/operator-api/src/kp_operator_api/console/onboarding.py` (or a small new route) — when `oidc_mode == "dev"` and the password is unset-or-default, return a flag the UI uses to show a one-time "Set your console password" form.
- `apps/operator-ui/src/console-js/app.js` — the form + capability gate.

**Validation:**
- New `test_first_run_credential.py`: unset → prompt shown; set → never logged/audited; weak password rejected; already-set → no prompt.
- `npm run build` regenerates the committed bundle; console wiring/drift tests green.

### A2 — Azure Graph client-ID discovery (WS3 remainder, deferred)

**Objective:** Stop asking the operator to copy the Entra app client IDs by GUID; return name+id pairs from `az ad app list --display-name`.

**Build:**
- `apps/operator-api/src/kp_operator_api/console/azure_deployment_routes.py` — read-only, capability-gated (`administrator`) discovery endpoint calling `az account show` / `az ad app list` and returning friendly-name → id pairs.

**Validation:**
- New `test_discovery_endpoints.py`: read-only, gated, name+id shape, non-blocking (a failed `az` call returns a friendly "could not discover" not a 500).
- **Open decision (blocks this task):** the API needs tenant-wide `Application.Read.All`; confirm the permission posture with the operator before building — this is a permission grant, not just code.

### A3 — Ciphertext active-key prefill (WS3 remainder, deferred)

**Objective:** Pre-fill `ciphertext_active_key_id` from the `ciphertext_keyring` Terraform output after foundation, instead of asking the operator to transcribe it.

**Build:**
- `apps/operator-api/src/kp_operator_api/deployment_orchestration.py` / `github_workflow_gateway.py` — surface the post-foundation keyring id in the plan projection the wizard reads; `azure_deployment_routes.py` pre-fills.

**Validation:**
- Extend `test_deployment_orchestration.py` (evidence-shape assertions) for the new field; confirm it stays read-only/fail-closed (never relaxes the ciphertext binding).

---

## B. On-prem operational gaps

### B1 — Boot persistence for the A3B model (operator action)

**Objective:** A3B auto-starts on Windows/WSL boot so a reboot does not silently drop the model.

**State:** WSL systemd `kp-aggregate.service` is re-enabled and points at the A3B `kp-aggregate-start.sh`. The Windows-side trigger (schtasks `KP-Aggregate-Model`) was deleted during the earlier clean-state work and must be recreated by the operator (Windows autostart creation is outside assistant scope).

**Command (operator runs on Alice):**
```
schtasks /Create /TN "KP-Aggregate-Model" /TR "wsl.exe -d Ubuntu-24.04 -u root -e systemctl start kp-aggregate" /SC ONLOGON /RL HIGHEST /F
```
> **The `-u root` matters.** WSL's default user on Alice is `erikd`, who cannot
> execute a root-owned script in `/root`. The earlier form of this command omitted
> `-u root` and invoked the start script directly: the task would have been created
> successfully and then failed silently at every logon — the exact failure B1 exists
> to prevent. Going through `systemctl start` is also idempotent. Use
> `scripts/operator/alice-boot-persistence.sh`, which does the SSH and verifies.

**Validation:** reboot Alice (or run the task manually) and confirm `/v1/models` on :18082 self-reports `qwen3-30b-a3b-aggregate` without any manual swap.

### B2 — Unattended periodic aggregation

**Objective:** The current-campaign ranking refreshes on a schedule so a human never has to remember to trigger it. (Confirmed absent: `main.py` has a scheduler, but it only runs `AuditStore.verify()`, not aggregation.)

**Build:**
- Add a bounded scheduler task (mirror the existing audit-verification scheduler in `apps/operator-api/src/kp_operator_api/main.py:409`) that POSTs `/aggregate` on an interval and stores the ranked candidates for review — gated so it never auto-promotes (promotion stays human-approved).

**Validation:**
- New `test_periodic_aggregation.py`: interval bounded, fails closed on gateway error, never auto-promotes, result written for human review.

---

## C. Validation gaps

### C1 — Aggregation eval: floor → ceiling

**Objective:** The current 3 cases are a floor — every candidate scored 3/3, so it proves "not worse" but not "better". Add hard cases to actually discriminate ranking quality.

**Build:**
- `scripts/ai-bakeoff/aggregation_evaluation_set.yaml` — add near-tie cases (two plausible campaigns, one marginally fresher), partial-relevance distractors, and multi-source grouping where only one source is current.

**Validation:**
- Re-run `aggregate_evaluate.py` against A3B (now the production model) on Alice; the report must still be `selection_evidence: true` and score the gold item rank-1 on every new case.

### C2 — Azure end-to-end integration test

**Objective:** The DNS click-to-copy (PR #32) and the whole Azure deploy path have never run end-to-end against a real Azure environment.

**Build/validate:**
- Dispatch a real `foundation_bootstrap` → `foundation_finalize` → `workloads` run and confirm: the four DNS records render click-to-copy in the console, `acs-delivery-readiness.json` is captured in every phase artifact, and the gateway's exact-path validation still passes with the new file.
- This is the only way to prove the Terraform-output capture in finalize/workloads works; it cannot be proven locally.

---

## D. Production / acceptance gates (standing NO-GO from AGENTS.md)

These are the hard blockers before production or RSA Conference use; each is evidence-bound, not code-only:

1. **Full suite green** — `make test`, `make lint`, `make typecheck` repo-wide, zero red.
2. **Exact-final-image** — native `linux/amd64` build pushed to the registry (build only on `.105`), not a local/dev image.
3. **Browser / WCAG** — accessibility pass on the console.
4. **Cloud / provider gates** — Azure provider/config-bound canary evidence with authenticated delivered receipts.
5. **Recovery** — proven restore from the migration checkpoint chain.
6. **Human-acceptance** — an actual non-technical operator drives a full campaign lifecycle on both paths without assistance.

---

## Sequencing

1. B1 (boot persistence) — operator, unblocks a reboot-safe state immediately.
2. A1 (first-run credential) + C1 (eval hardening) — both self-contained, high-value.
3. B2 (periodic aggregation) — depends on A3B being permanent (done).
4. A2 + A3 (Azure discovery/prefill) — after the permission decision (A2).
5. C2 (Azure integration) — after A2/A3 land, needs a live Azure environment.
6. D (production gates) — continuously, evidence-bound; not a "finish" so much as a set of proofs.

## Risks / open questions

- A2 needs a tenant-wide permission grant — a security decision, not a code decision; do not silently expand scope.
- C2 needs a live Azure subscription + the operator's Entra/admin steps; cannot be simulated.
- Privacy contract: the pseudonymous ledger drill-down deliberately withholds names — do NOT "fix" that.
- Boot persistence (B1) is classifier-blocked for the assistant; the operator must run the schtasks command.
