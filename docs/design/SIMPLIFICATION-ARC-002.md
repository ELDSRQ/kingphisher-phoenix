# ARC-002 — Simplification / complexity reduction

**Task:** ARC-002 (P2) · from `docs/design/REVIEW-FINDINGS-2026-09.md` (architect G3/G4/G7 + senior-dev tech-debt).
Date 2026-09-06. **Goal:** cut complexity for a two-operator, single-tenant product **without weakening any safety guarantee** (the "don't break" core in REVIEW-FINDINGS stays intact). Sequenced low-risk-first; each item notes whether it is behavior-preserving refactor vs. an interface change.

> Authored by the main session after the ARC-002 subagent was interrupted by a usage limit; content is the consolidated architect + senior-dev findings, verified against the tree.

## The core problem (why this matters)
The operator API's complexity budget is inverted toward **Azure deployment orchestration** that is now idled: ~4,600 lines of deploy/GitHub-dispatch/Terraform-plan code live *inside* the operator API, comparable to the entire campaign router, and the largest test file in the repo is the deployment-orchestration test. For two non-specialist operators of a *locally-running* product, that is maintenance drag + attack surface (a GitHub token + a Redis-leased plan state machine in the control plane) with little day-to-day value.

## Item 1 (highest payoff / lowest risk) — Quarantine the Azure deploy connector
- **Now:** `deployment_orchestration.py` (~2,024), `github_workflow_gateway.py` (~728), `deployment_common.py` (~565), and ~1,300 lines of Azure routes in `console.py` (`_azure_release_readiness`, `validate_azure_deployment`, `advance_azure_deployment_plan`). It holds GitHub-dispatch authority + a `RedisPlanStore` state machine. The GUI stage model can't even represent the idle state (the CI hardcodes `deploy_workloads=true` over tfvars — related bug).
- **Phase 1 (reversible, no behavior change for users who keep it on):** gate all of it behind a `deploy_connector_enabled` flag (default preserves today); hide the Deployment nav when off. A locally-run install ships with it **off** → the whole surface disappears.
- **Phase 2 (interface change):** replace GUI-driven GitHub dispatch with the existing runbook scripts (`scripts/operator/deployment-preflight/*`) — same fail-closed checks, **no GitHub token in the control plane**. Fold in the CI-precedence fix (workflow must honor tfvars).
- **Payoff:** removes the largest non-core surface + a credential from the control plane. **Risk:** low (flag-gated, additive first).

## Item 2 — Split the god-modules along the clean seams the reviews identified
Behavior-preserving refactors; precedent already exists (`content_library.py`, `threat_routes.py`, `program_routes.py` are split out).
- **`routers.py` (~4,711)** → by resource: `audience_groups` / `campaigns` / `sources` / `recipients` / `alerts` / `patterns` / `dead_letters` / `audit+kill_switch` / `privacy`.
- **`console.py` (~3,658)** → `env_store` / `console_auth` / `config` / `azure_deployment_routes` (moves with Item 1) / `onboarding` / `runtime_status`.
- **`process_delivery` (`jobs.py:1274`, ~471 lines / 68 branches)** → `claim` / `gate` / `render` / `send` / `record`; and the per-recipient cost of `_launch_delivery_gate_reason` (it re-reads+re-hashes a 10k-row canary manifest per recipient today). **DO NOT hoist that call out of the loop** — attempted 2026-09-07 and proven unsafe: each iteration is a new transaction re-acquiring the launch gate, so hoisting sent real mail to a whole batch whose gate had been revoked mid-batch. See `docs/design/ARC-002-ITEM2-WAVE.md`. Fix the cost in SQL instead, as a separate reviewed task.
- **Risk:** low if done as pure moves with the suite green each step; **do NOT** change the gate *sequence* (that's a safety invariant — pair with the single-gate-list idea in PLT/AUT work).

## Item 3 (evaluation, not a mandate) — Postgres-only queue (drop Redis)
- **Now:** every mutation stages in `transactional_outbox`; a dispatcher copies to Redis; workers consume via 15 Lua scripts (`packages/contracts/queue.py`); delivery is at-least-once with business idempotency required. Rate-limiting already has a memory backend.
- **Proposal:** at **125 recipients**, a `SELECT … FOR UPDATE SKIP LOCKED` consumer on the outbox itself can replace Redis + the Lua contract + the DB14/DB15 test profiles + `RedisPlanStore` + the `deploy_data_plane` Redis cost — with **zero loss of safety** (all locks/guarantees live in Postgres).
- **Risks to design for:** throughput ceiling, visibility-timeout/lease semantics, delayed-retry (currently a Redis ZSET). **This is a recommendation to evaluate**, sequenced after Items 1–2; prototype the consumer behind a flag and A/B before removing Redis.

## Item 4 — Shared `kp_web` helpers (kill drifted duplication)
The reviews found byte-identical / drifted copies across app boundaries: `BodyLimitMiddleware` (operator vs tracking — the fork already cost operator-api a middleware), `RequestTargetLimitMiddleware`, ~12 hex-key validators, five canonical-JSON serializers feeding hashes, `bounded_validation_message`, the `get_session` dependency. Extract a small `kp_web` package (behavior-preserving) so security-relevant helpers have one definition. **Risk:** low; keeps the acyclic package graph (new leaf package).

## Sequence (by payoff / reversibility)
1. **Item 1 Phase 1** — flag-gate the Azure connector (reversible, immediate surface + risk reduction). ← do first.
2. **Item 4** — `kp_web` helpers (removes drift that has already caused security-relevant divergence).
3. **Item 2** — split god-modules (behavior-preserving, unlocks the routers split the plan already wants).
4. **Item 1 Phase 2** — retire GUI GitHub-dispatch for runbook scripts.
5. **Item 3** — evaluate/prototype Postgres-only queue; adopt only if the A/B holds.

**Single highest-payoff, lowest-risk first move:** Item 1 Phase 1 (flag-gate + hide the Azure deploy connector) — it removes the biggest non-core surface and a control-plane credential with a purely additive, reversible change, and a locally-run two-operator install never sees it.
