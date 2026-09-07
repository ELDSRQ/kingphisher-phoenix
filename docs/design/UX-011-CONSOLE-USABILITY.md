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
| 2 | Rendered-HTML preview + send-to-self | **2a DEFERRED / 2b DONE** | **2a rendered HTML preview: REVERTED for safety** — a sandboxed `srcdoc` preview violates the console's no-live-HTML invariant (`.srcdoc`/`.innerHTML` forbidden); the preview keeps the safe plain-text-only frames. A safe HTML-structure view would need a *server-side* structural summary, not client rendering — recorded as a follow-up. **2b proof send: DONE** — `POST /campaigns/{id}/proof-send` + `process_proof_send`. See "§2b proof send — as landed" below; the destination is server-derived and deliberately NOT the `{recipient_id}` body field the original proposal sketched. |
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
| `POST /campaigns/{id}/proof-send` | `create:campaign` \| `approve_security` \| `approve_privacy` (no new capability) | `test_proof_send.py`, `test_proof_send_job.py`, `test_route_authorization_inventory.py`, `test_ux011_console_wiring_contract.py` | PASS |
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

- ~~**Proof send-to-self (2b)**~~ — landed; see "§2b proof send — as landed" below.
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

---

## §2b proof send — as landed

`POST /api/v1/campaigns/{campaign_id}/proof-send` mails **one** rendered copy of a
campaign's own message to the operator's test mailbox so an author or approver can
see how the lure actually lands, before a decision is recorded. It is a REAL
outbound message and is treated as one.

### The security property, and the deliberate deviation from the proposal

`CONSOLE-USABILITY-UX-011.md` §2b sketched `POST …/proof-send {recipient_id}` with a
console picker. **That was not built.** A caller-supplied destination — even one
validated against `is_test_account` — makes the console a selector of *where real
mail goes*, and that is the one property this feature must not have.

As landed, **the destination never appears in the request**:

- `ProofSendRequest` carries only `confirm` and `reason` and is
  `ConfigDict(extra="forbid")`, so `{"mailbox": …}` / `{"recipient_id": …}` is a
  **422**, not a silently dropped field.
- `_designated_proof_recipient(session)` selects the deterministic first
  (`ORDER BY recipient_id`) row that is `is_test_account = True`, `ACTIVE` and not
  soft-deleted. That designation is the *existing* server-designated test-account
  mechanism the canary cohort already uses (`bind_campaign_launch_review`): only a
  `manage:recipients` holder can set it, it requires `confirm` + a reason, it is
  audited as `recipient.test-account.update`, and it is locked while the recipient
  belongs to a frozen or assigned live campaign.
- The queue payload carries a **recipient id, never a mailbox**. The worker
  (`process_proof_send`) re-loads the row and re-checks the designation before it
  touches a provider, so a designation revoked between enqueue and dispatch sends
  nothing.
- The response reports which designated account was used (`proof_recipient_id`,
  and `masked_mailbox` only for `view_named:results` holders, the same privacy
  boundary as every other recipient projection). The choice is **visible without
  ever being selectable**.

### Gates, all revalidated server-side

| Control | Where |
|---|---|
| Capability (`create:campaign` \| `approve_security` \| `approve_privacy`) — **no new capability** | `require_any_capability` on the route; registered in `test_route_authorization_inventory.py` |
| Campaign state ∈ {`DRAFT`, `PENDING_APPROVAL`} | route **and** worker (`_PROOF_SEND_CAMPAIGN_STATES`) |
| Global emergency stop | route (`_system_safety_state(shared_lock=True)`) **and** worker, re-read under the shared lock immediately before the provider call |
| Recipient-domain allowlist | route (`resolve_recipient_policy` — PLT-002 fail-closed 422 on an unset allowlist outside a marked dev stack) **and** worker (`is_recipient_allowed`, `unrestricted` computed exactly as in `process_delivery`) |
| Bound RoE target domains | route and worker, whenever `campaign.roe_id` is set (before review there is usually none; this check can only ever refuse more) |
| Exclusions / delivery suppression | worker (`_excluded_recipient_ids`, `RecipientDeliverySuppression`) |
| Never a live recipient of this campaign | route and worker refuse if a `RecipientAssignment` exists for (campaign, proof recipient) |
| Throttle | two fail-closed `RateLimiter` windows on `app.state` — 3 per actor and 10 per deployment per 5 minutes — Redis-backed exactly when the process-wide user limiter is |
| Audit | `campaign.proof-send.queued` (route), `campaign.proof-send` / `.failed` (worker), and `campaign.proof-send.blocked` on **every** refusal in both |
| Audit-health gate | the route is unsafe and NOT in `_AUDIT_GATE_EXEMPT_ROUTES`, so it 503s when the audit chain is unhealthy |

### What a proof deliberately is not

It creates **no** `RecipientAssignment`, **no** `TrackingToken`, **no**
`DeliveryCorrelation`, **no** canary evidence and **no** approval; it writes no
campaign, launch-gate, audience or send state. The only rows it writes are the
transactional-outbox message and audit events. Content is rendered by the same
renderer, through the same static-training-URL fence and the same
`SafetyValidator` verdict as delivery, but with a synthetic non-persisted
`proof-…` tracking identifier, so a click or open from a proof resolves to
nothing and can never become evidence, a training assignment or a followup. The
subject is prefixed `[PROOF] ` and an `X-KP-Proof-Send: 1` header is set. No open
pixel and no calendar attachment are added — both are recipient-bound artefacts
of a real send.

The template does **not** need to be approved: seeing the message before approving
it is the point. The deterministic content safety validation still runs on the
rendered result, and the destination is still only a designated test mailbox.

### Operator browser validation required

7. The **"Send proof to test mailbox"** button appears for a campaign in
   `DRAFT`/`PENDING_APPROVAL` for an author or approver, the dialog offers a
   reason and **no destination field**, and the resulting message arrives at the
   designated test account with a `[PROOF]` subject. Engaging the emergency stop
   must make the same button refuse.
