# Review Findings — 2026-09

_Date: 2026-09-06 — consolidated read-only review by four perspectives (architect / senior dev / security analyst / portability)._

This document is the consolidated synthesis of four independent, read-only reviews of the
phishing-awareness platform. It is analysis only; no code, Terraform, or scripts were changed
in producing it. The tracked remediation tasks derived from it live in
[`docs/WAVE-BUILD-PLAN.md`](../WAVE-BUILD-PLAN.md) under IDs `PLT-002`, `AUT-002`, `AUD-002`,
`DEL-002`, `OPS-002`, `AI-016`, `AUD-003`, `CNT-002`, `ARC-002`, `UX-011`, and `TST-002`.

---

## Headline — the convergence

All four reviewers converge on the same picture: **the safety core is genuinely well-built —
do not touch it.** The systemic problem is that **"managed" is conflated with "Azure"**: there
is no first-class **LOCAL-HARDENED** posture.

The local deployment now running is the **disposable DEV posture**:

- dev auth = a shared blanket-admin password,
- every service connects as the **DB OWNER**,
- single-admin approvals,
- no audit witness,

while roughly **one third of the codebase's complexity serves the now-idled Azure path**. This
is the structural root of **KP-008** (least-privilege was never exercised locally).

**Highest-value change:** separate *how hardened* from *which host*, so a fully-featured **and**
fully-safe deployment can run locally.

---

## Prioritized findings

Each finding notes the reviewer(s) who flagged it, the evidence (with `file:line` where given),
and the fix.

### P0

**P0-1 — `managed == Azure` / unsafe-by-default cluster** _(architect, portability, developer,
security — 4/4)_
Unsafe defaults: `approval_policy=SINGLE_ADMIN`, `oidc_mode=dev`; dev-mode is not refused under
managed config.
- Evidence: `apps/operator-api/.../config.py:182-187`, `apps/workers/.../config.py:263-266`.
- Impact: one env flip collapses separation-of-duties, allows all recipients, and drops ACS
  ingress checks.
- Fix: introduce a posture/profile axis with **per-provider** (not per-mode) validators; default
  to **ENFORCE**; refuse `oidc_mode=dev` under managed; run least-privilege roles locally.
- Tracked as **PLT-002**.

**P0-2 — Two-person approval is two-LANE, not two-PERSON** _(security, S1)_
One `ADMINISTRATOR` holds both `APPROVE_SECURITY` and `APPROVE_PRIVACY`; approver identity is
never compared, so a single admin can approve both facets — fully audited but not separated.
- Evidence: `routers.py:1505-1516`, `rbac.py:151-178`, `jobs.py:1345-1356`.
- Fix: require two **distinct** people — reject `approver_id == other approver` and
  `approver_id == submitter`; worker must require `len(distinct approver_id) >= 2`.
- Tracked as **AUT-002**.

**P0-3 — Grant matrix scattered + only string-tested (KP-008 root)** _(developer #2, architect
G5, security S3)_
Grants are spread across 6 Alembic revisions + `scripts/azure_migrate.py:35` + bootstrap +
`001-roles.sh`, and are verified by asserting **SQL text**, not effect
(`test_migrations_azure_bootstrap.py` is mock-based). Non-Azure installs leave `audit_writer`
**OWNER** of audit tables (`0010:70`, `001-roles.sh:44`) — it can `UPDATE`/`DELETE` audit rows.
- Fix: one importable **grant matrix** consumed by every path + a runtime probe; per-role
  `has_table_privilege` tests (true-in-slice / false-outside); an autogenerate/drift gate.
- Tracked as **AUD-002**.

**P0-4 — Delivery safety bugs** _(developer #3/#4, security S5/S6)_
- `AzureCommunicationEmailSender` has **no timeout** (`smtp.py:376-378`) while the worker holds
  `FOR UPDATE` (`jobs.py:1019`) / `FOR SHARE` (`jobs.py:690`) locks the kill-switch needs — a
  hung send blocks emergency stop.
- A broad `except` (`jobs.py:1682`) files **definite** non-sends as `INDETERMINATE` (never
  retried) — recipients are stranded.
- Reminders bypass the gate (`followup_jobs.py:41-185`: no safety / RoE / allowlist / exclusion).
- Exclusions are enforced at publish, not send.
- Canary `test_send=True` disables template-approval + two-person re-checks for real mailboxes
  (`jobs.py:1337,1345`).
- Mail-scanner prefetch = first-wins `CLICKED` → training assigned and reminders sent to a named
  employee who never clicked (`tracking routers.py:491-568`, `followup_jobs.py:40-60`).
- Fix: add an ACS send timeout so a hung send can't block the emergency-stop locks; narrow the
  broad `INDETERMINATE` except so definite failures aren't stranded; bring reminders/exclusions
  under the send gate; drop the `test_send` skips.
- Tracked as **DEL-002**.

### P1

**P1-1 — No CI** _(developer #1)_
All workflows are `workflow_dispatch` only (`azure-deploy.yml:20`, etc.); `main` is unprotected;
postgres/redis gates run only in the manual workloads deploy.
- Fix: add `ci.yml` on PR + `push:main` running lint/typecheck/test + `uv lock --check` +
  postgres/redis gates; protect `main`.
- Tracked as **OPS-002**.

**P1-2 — ai-gateway unhardened** _(developer #6, security S12)_
- No bearer check although workers send one (`jobs.py:2088`).
- `training_url` is interpolated **unescaped** into `safe_html` (`main.py:141`) — XSS into
  generated content.
- Guidance **replaces** the system prompt (`main.py:109`).
- Backend errors are unguarded (`main.py:158-162`).
- Internal-only ingress mitigates but does not fix. Pairs with **AI-015** (Foundry adds an authed
  backend anyway).
- Fix: require the bearer, `html.escape` the `training_url`, make guidance bounded/replace-safe,
  wrap backend errors.
- Tracked as **AI-016**.

**P1-3 — Audit witness is write-only / absent locally** _(security S3, architect G1, portability)_
- Anchors are written but never read back / compared (`audit_anchor_jobs.py:39-76`).
- A stalled anchor does not disable mutations (`main.py:214-225`).
- No local anchor provider (absent from `scripts/supervisor.py:31-42`).
- Fix: a **local WORM/MinIO object-lock** anchor provider + read-back chain verify + alerting;
  gate mutations on last-anchor age so tamper-evidence works offline.
- Tracked as **AUD-003**.

**P1-4 — Jinja sandbox not applied** _(security S7)_
`_ALLOWED_GLOBALS` is declared but never enforced (`render.py:22,77-87`), so
`{{ "x"*10**9 }}` allocates ~1 GB in API and worker.
- Fix: clear globals/filters, cap binops/output, timeout preview.
- Tracked as **CNT-002**.

### P2

**P2-1 — Simplification** _(architect G3/G4/G7, developer)_
- ~4,600 lines of Azure deploy orchestration live **inside** the operator API (GitHub-dispatch
  authority in the control plane).
- `routers.py` / `console.py` / `process_delivery` are god-modules with clean seams.
- Redis is removable via Postgres `SKIP LOCKED` at 125 seats.
- Fix: quarantine the in-operator-API Azure deploy connector behind a flag; split the god-modules
  along their seams; evaluate a Postgres-only queue (drop Redis) at 125 seats.
- Tracked as **ARC-002**.

**P2-2 — Docs** _(architect G9, developer)_
Four contradictory handoffs; `.140`-vs-`.105` contradictions; tracked operator lore
(`.dep010-run`, `.140` contract tests). (Covered by the existing `DOC-001` lane; noted here for
completeness.)

---

## Usability / interface findings

From the security reviewer (U1–U11). Keep it simple and intuitive — **no safety gate is touched**.

- Recipients are shown as 8-char UUIDs everywhere you pick people — you can't choose
  "Jane in Finance."
- No rendered HTML preview / send-to-self before approval.
- Emergency stop is unreachable for the operator role (buried under Audit, which operators can't
  view).
- Nothing is cloneable — you retype the form and re-sign the RoE each time.
- No approver "needs my decision" queue.
- No send-time spread — 125 recipients get it in minutes.
- Thin evidence export — `report.csv` is unwired from the GUI.

Fix (tracked as **UX-011**): masked recipient **display names** instead of UUIDs; rendered HTML
preview + send-to-self before approval; a reachable emergency stop for the operator role;
clone-campaign + re-sign-RoE; an approver "needs my decision" queue; send-time spread/scheduling;
wire `report.csv` + evidence-bundle export.

---

## "Don't break" list

All four reviewers converge: the security architecture is genuinely strong; fixes live **around**
it, never through it.

- Transactional outbox + DB-owned SECURITY-DEFINER audit signer.
- Two-phase canary→publish, with the worker re-verifying the manifest hash.
- Frozen-audience DB trigger.
- Persistent emergency stop.
- Capability RBAC + the 113-route inventory test.
- Tracking edge: opaque bearers, keyed verifiers, IP minimization, trusted proxies.
- OIDC egress hardening.
- The ai-gateway `/propose` seam.
- The CipherText keyring.

---

## Portability design summary

From the fourth (portability) reviewer.

**Separate hardening from hosting.** `runtime_mode` (how hardened) is orthogonal to hosting
(backend enums per capability), and both are selected by one **`KP_PROFILE`**:
`local-dev` / `local-hardened` / `azure`.

**Per-capability backend enums:**

| Capability | Backends |
|---|---|
| identity | Keycloak / Entra |
| directory | none / mock / graph |
| reported-mailbox | mailpit / imap / m365 |
| email | smtp / acs |
| receipts | none / smtp / acs_eventgrid |
| AI backend | llama / openai_compatible (= Foundry = AI-015) |
| audit-anchor | local_worm / s3_object_lock / azure_blob |
| secrets | env_file / managed |
| DB / cache | local / azure |

**Three gaps to close for full local operation:**

1. A **local audit-anchor provider**.
2. A **private-issuer OIDC allowance** — IAM-003 path (b) promoted to required; `auth.py:229-235`
   SSRF blocks LAN issuers today.
3. A **receipts abstraction** — drop `CHECK provider IN ('acs')` at
   `models.py:862,894,919`.

Also make `azure-identity` imports an **opt-in extra** (currently module-level in `graph.py`,
`microsoft365.py`, `audit_anchor.py`).

Composes with **D-0001** (AI row) and **IAM-003** (identity row).

**Irreducible cloud for a REAL external send:** a verified sending domain; public SPF/DKIM/DMARC
DNS + reputation; public HTTPS for tracking links; a bounce/complaint webhook. Keep that boundary
thin and opt-in behind `KP_PROFILE=azure`.

---

## Recommended sequence

1. **PLT-002** — establish the posture/profile axis and least-privilege-locally (the structural
   root; unblocks honest local hardening). Depends on IAM-001 / IAM-003.
2. **AUD-002** — grant matrix as single source of truth + per-role effect tests + drift gate
   (closes the KP-008 class, including `audit_writer` owning audit tables locally).
3. **AUT-002** — two distinct approvers.
4. **DEL-002** — delivery safety bugs (ACS timeout, narrowed `INDETERMINATE`, reminders/exclusions
   under the gate, drop `test_send` skips).
5. **OPS-002** — CI on PR + `push:main`, protect `main` (guards every subsequent change).
6. **AI-016** — harden ai-gateway (pairs with AI-015).
7. **AUD-003** — local audit-anchor provider + read-back verification + alerting.
8. **CNT-002** — actually apply the Jinja sandbox.
9. **UX-011** — console usability for the security-analyst operator (no safety gate touched).
10. **ARC-002** — simplification (P2, after the P0/P1 safety work stabilizes).
11. **TST-002** — test-effect uplift (P2; run on the migrated schema, live Redis, Playwright smoke).
