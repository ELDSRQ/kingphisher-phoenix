# UX-011 — Console usability for a security-analyst operator (implementation record)

_Date: 2026-09-06. Built to the design proposal in
[`CONSOLE-USABILITY-UX-011.md`](CONSOLE-USABILITY-UX-011.md). This file records
what actually landed, what was deferred and why, and the safety confirmation._

## Absolute invariant — confirmed held

**No capability gate, approval, RoE, or kill-switch behaviour changed.** Every
change is usability/visibility only:

- No route's required capability was loosened. Two **new** routes were added, each
  behind an existing capability and registered in the authorization inventory test
  (`test_route_authorization_inventory.py`): `GET /campaigns/needs-my-decision`
  (`approve_security` OR `approve_privacy`, read-only) and
  `GET /campaigns/{id}/evidence.zip` (`export_bulk`, read-only).
- The emergency stop became **more reachable, never weaker**: the identical
  audited flow (`POST /kill-switch` / `/kill-switch/reset`, `use:kill_switch`,
  `confirm=true` + reason server-side) is now surfaced in the sidebar footer for
  `use:kill_switch` holders. The Audit view uses the same shared control instead
  of a second implementation. No endpoint, capability, or confirm requirement
  changed.
- The AUT-002 two-distinct-approver rule is **already enforced server-side** in
  `approve_campaign` (self-approval, submitter, and "already approved a facet"
  are all rejected there — unchanged). UX-011 only narrows the read-only UI flag
  `can_approve_*` in `_campaign_action_flags` so the "needs my decision" queue and
  the per-row buttons stop offering a decision the server would reject. This is a
  fail-closed UI change, not a gate change.
- The rendered-HTML preview (§2a) was **reverted during integration**: rendering the
  sanitized `safe_html` in a sandboxed `srcdoc` iframe conflicts with the console's
  standing safety invariant — template HTML is *deliberately not executed in the
  operator console* (`test_operator_ui_campaign_readiness`, which forbids `.srcdoc`
  and `.innerHTML` in the console entirely). Even an opaque-origin `sandbox=""`
  frame is a live-render path the invariant does not permit. The preview therefore
  keeps the pre-existing safe behavior: desktop/mobile/plain frames show only the
  approved **plain-text body**, and the HTML alternative is disclosed but never
  rendered. The server renderer and `_CONSOLE_CSP` are untouched.
- Clone re-enters the front of the pipeline: it only prefills the create form, so
  the new campaign is a fresh unapproved `DRAFT` with no approvals and no RoE by
  construction. Re-signing an RoE always produces a new signature; the source RoE
  is untouched.

## Deliverables — DONE / DEFERRED

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | Masked recipient display names | **DONE** | `list_recipients` and `campaign_recipient_results` add `display_name` + `masked_mailbox` for `view_named:results` holders only (reusing `_masked_mailbox`); `?mailbox=` exact salted-digest lookup added. Console `recipientReference()`/`recipientPickerLabel()` replace `.slice(0,8)` in the outcomes table, recipients table and audience pickers. The pseudonymous **ledger drill-down is intentionally NOT masked-labelled** (privacy contract `test_..._never_renders_identity_or_pseudonym`). |
| 2 | Rendered-HTML preview + send-to-self | **DEFERRED** | **2a rendered HTML preview: REVERTED for safety** — a sandboxed `srcdoc` preview violates the console's no-live-HTML invariant (`.srcdoc`/`.innerHTML` forbidden); the preview keeps the safe plain-text-only frames. A safe HTML-structure view would need a *server-side* structural summary, not client rendering — recorded as a follow-up. **2b proof send-to-self: DEFERRED** — requires a worker job (`apps/workers/.../jobs.py`) and the server-designated test-account send path, both outside the write allowlist. See "Out-of-allowlist follow-ups". |
| 3 | Emergency stop in primary nav | **DONE** | Sidebar footer control for `use:kill_switch` holders; shared `globalStopButton`/`toggleGlobalStop` reused by Audit. Visibility only. |
| 4 | Clone campaign forcing re-sign RoE | **DONE (Phase 1, client-side)** | "Clone as new draft" prefills the create form; "Re-sign for a new window" prefills `signRoe`. Both start fresh; no approvals/RoE carried over. Optional Phase 2 server `POST /campaigns/{id}/clone` audit line not added (not required by the invariant). |
| 5 | Approver "needs my decision" queue | **DONE** | New `GET /campaigns/needs-my-decision` server endpoint (AUT-002-aware via the tightened flags) + dashboard card + sidebar badge. |
| 6 | Send-time spread / scheduling field | **DEFERRED** | The data + freeze integrity require `Campaign.pacing` (a column + Alembic revision in `packages/database/.../models.py`), inclusion in `campaign_launch_review_manifest_hash` (`campaign_service.py`), a `plan_delivery_batches` helper, and per-batch `available_at` in the worker — all outside the write allowlist. Wiring a UI field that the server silently ignored would mislead the operator, so nothing was wired. Full plan is in `CONSOLE-USABILITY-UX-011.md` §6. |
| 7 | report.csv + evidence-bundle export | **DONE** | `report.csv` (pre-existing endpoint) wired via a new allow-listed `downloadCampaignExport` helper; new read-only `GET /campaigns/{id}/evidence.zip` (`export_bulk`) added and wired. Both bounded by the same 5 MB streaming cap; the evidence bundle contains `campaign.json`, `approvals.json`, `roe.json` and a `manifest.sha256`, and never includes mailboxes or display names. |
| + | ARC-002 nav-hide follow-up | **DONE** | `canNavigateTo` hides `azure-deployment` when `/console/auth-mode` reports `deploy_connector_enabled === false`. Presentation only; the connector routes are already server-gated. |

## New endpoints and their tests

| Endpoint | Capability | Tests | Status |
|---|---|---|---|
| `GET /campaigns/needs-my-decision` | `approve_security` \| `approve_privacy` | `test_needs_my_decision.py` (flags tightening + endpoint projection), `test_route_authorization_inventory.py` | PASS |
| `GET /campaigns/{id}/evidence.zip` | `export_bulk` | `test_evidence_bundle.py`, `test_route_authorization_inventory.py` | PASS |
| `GET /recipients?mailbox=` (+ masked fields) | existing | `test_recipient_masking.py`, `test_recipient_pagination.py` | PASS |
| `GET /campaigns/{id}/recipients` (+ masked fields) | existing `view_named:results` | `test_recipient_pagination.py`, `test_recipient_masking.py` | PASS |

Console wiring is covered by `test_ux011_console_wiring_contract.py` (reads
`console-js/app.js`). Full suite: **1040 passed, 54 skipped**.

## Operator browser validation required (I did NOT run a browser)

The visual/interaction correctness of the console is validated by the operator,
not by this agent. Please verify in a real browser:

1. The sidebar **Emergency stop** control shows for a `campaign_operator` session
   and is **absent** for `security_approver` / `privacy_approver`; engaging and
   resetting behaves exactly as the Audit control did.
2. The **template preview** offers Desktop / Mobile / Plain-text frames, each
   showing the approved **plain-text body only** — no HTML is executed or rendered
   in the console (the §2a `srcdoc` approach was reverted for the no-live-HTML
   safety invariant). The "sanitized HTML alternative exists but is deliberately
   not executed" notice is shown when a `safe_html` is present.
3. "Azure deployment" disappears from the nav when the deploy connector is off.
4. The **"Needs my decision"** card count equals the number of campaigns with an
   open lane for the signed-in approver, and the Campaigns nav badge matches.
5. The **Clone** and **Re-sign RoE** prefills populate the right fields.
6. WCAG / assistive-tech review of the new controls (operator-gated).

## Out-of-allowlist follow-ups (NOT edited — recommendations only)

These were required for full delivery of items 2b and 6 but fall outside the
write allowlist; they need explicit approval and their own gate review:

- **Proof send-to-self (2b):** `POST /campaigns/{id}/proof-send` + worker
  `process_proof_send` in `apps/workers/src/kp_workers/jobs.py`, sending only to a
  server-designated test account, creating no assignment/token/evidence, honouring
  the emergency stop at enqueue and send. `routers.py` is in the allowlist but the
  worker is not, so the endpoint was not added (an enqueue with no consumer would
  be worse than none).
- **Delivery pacing (6):** `Campaign.pacing` column + Alembic revision
  (`packages/database/.../models.py`), pacing folded into
  `campaign_launch_review_manifest_hash` (`campaign_service.py`), a unit-tested
  `plan_delivery_batches`, and per-batch `available_at` in the publish path/worker.
- **Recommended audit lines (read paths):** `recipients.exact_lookup` for the
  `?mailbox=` lookup and `results.export` on `report.csv`/`evidence.zip`. Not added
  to avoid write-on-GET semantics; worth adding when the exact-lookup privacy
  signal is wanted.
- **Authoring-seam note:** the console is authored in
  `apps/operator-ui/src/console-js/app.js` and bundled by esbuild to the committed
  `apps/operator-ui/src/console/app.js` (the file named in the allowlist). Every UI
  contract test and the drift gate read the `console-js/` source, so the JS changes
  had to land there; the committed bundle was regenerated with
  `cd apps/operator-ui && npm run build` and both files are committed together. The
  drift gate (`test_console_bundle_drift.py`) passes with a fresh esbuild build.
