# UX-011 — Console usability for two IT operators (no safety gate touched)

_Date: 2026-09-06 — design proposal only. No application code changed. Tracked as `UX-011` in
[`docs/WAVE-BUILD-PLAN.md`](../WAVE-BUILD-PLAN.md); derived from the U1–U11 usability findings in
[`REVIEW-FINDINGS-2026-09.md`](REVIEW-FINDINGS-2026-09.md#usability--interface-findings)._

## 0. Scope, audience, ground rules

**Audience.** Two IT operators run this platform: in practice one person authors and runs
campaigns (`campaign_author` + `campaign_operator`) and the other approves (`security_approver`
and/or `privacy_approver`), with an `administrator` account held in reserve. Everything below is
sized for that team, not for a large SOC.

**Ground rules (apply to every item).**

1. **No safety gate is weakened.** The frozen-audience manifest, two-phase canary→publish, RoE
   coverage, the persistent emergency stop, capability RBAC, the outbox and the audit chain are
   the "don't break" list in the review. Each item below states explicitly how it relates to the
   gates. Where an item *interacts* with a gate, the gate stays server-side and unchanged; the UI
   only becomes a better window onto it.
2. **Framework-free UI.** The console is a single committed IIFE bundle
   (`apps/operator-ui/src/console/app.js`) built from ES-module sources in
   `apps/operator-ui/src/console-js/` by `apps/operator-ui/scripts/build-console.mjs`
   (deterministic esbuild, no minify). All UI work lands in `console-js/app.js` and is rebuilt
   into `console/app.js`; both files are committed together. Line references below cite the
   committed bundle (`console/app.js`) because that is what was verified; the `console-js` anchor
   is given where the edit lands.
3. **Every new route** must be added to the capability inventory test
   `apps/operator-api/tests/test_route_authorization_inventory.py` (it enumerates every operator
   route with its required capability) and must not alter `_CONSOLE_CSP`
   (`apps/operator-api/src/kp_operator_api/main.py:738`, pinned by
   `apps/operator-api/tests/test_console_csp_contract.py:64-69`).
4. **Bounded, allow-listed downloads.** Any new download goes through `downloadApiCsv`
   (`console/app.js:249-270`): path allow-list, 5 MB cap (`:211`), content-type check (`:226`).

**Verified capability facts used throughout** (`packages/authorization/src/kp_authorization/rbac.py`):

| Role | Has | Lacks (relevant here) |
|---|---|---|
| `campaign_operator` (`rbac.py:136-149`) | `SCHEDULE_CAMPAIGN`, `SEND_CAMPAIGN`, `STOP_CAMPAIGN`, **`USE_KILL_SWITCH`**, `VIEW_AGGREGATE`, `MANAGE_RECIPIENTS`, `VERIFY_DOMAIN`, `SIGN_ROE`, `MANAGE_QUEUE` | `VIEW_AUDIT`, `VIEW_NAMED_RESULTS`, `EXPORT_BULK`, `CREATE_CAMPAIGN` |
| `security_approver` (`:123-125`) | `APPROVE_SECURITY`, `APPROVE_TEMPLATE`, `VIEW_NAMED_RESULTS`, `VIEW_AGGREGATE`, `STOP_CAMPAIGN` | `USE_KILL_SWITCH`, `VIEW_AUDIT`, `EXPORT_BULK` |
| `privacy_approver` (`:126-135`) | `APPROVE_PRIVACY`, `HANDLE_PRIVACY`, `DELETE_DATA`, `VIEW_NAMED_RESULTS`, `MANAGE_EXCLUSIONS` | `USE_KILL_SWITCH`, `VIEW_AUDIT`, `EXPORT_BULK` |
| `campaign_author` (`:122`) | `CREATE_CAMPAIGN`, `VIEW_AGGREGATE` | `VERIFY_DOMAIN`, `VIEW_NAMED_RESULTS` |
| `auditor` (`:150`) | `VIEW_AUDIT`, `VIEW_NAMED_RESULTS`, `VIEW_AGGREGATE` | `EXPORT_BULK` |

Note that **`EXPORT_BULK` is administrator-only** (`rbac.py:163`). Several export items below
therefore need a deliberate decision about whether `auditor` / approvers get it (Section 7).

---

## 1. Recipient display names instead of 8-char UUIDs (U1)

### Current gap

- `GET /recipients` returns only `recipient_id`, `department`, `status`, `is_test_account`
  (`apps/operator-api/src/kp_operator_api/routers.py:2760-2786`), for callers holding
  `VIEW_NAMED_RESULTS` *or* `MANAGE_RECIPIENTS` (`:2765-2767`). No mailbox, no display name.
- `GET /campaigns/{id}/recipients` (`routers.py:2230-2350`, gated `VIEW_NAMED_RESULTS` at
  `:2236`) deliberately omits mailboxes; the docstring (`:2238-2244`) explains the intent:
  operators need to know *which assignments* failed, not who clicked.
- The console therefore truncates the UUID everywhere a person is chosen or shown:
  recipient outcomes table `console/app.js:713`; audience-group member picker `:2618`;
  campaign include/exclude pickers `:2685`; ledger drill-down picker `:4298` and status line
  `:4258`; Recipients table `:5678`, `:5687`, `:5701`; test-account and exclusion dialogs
  `:4990`, `:5071`.
- The masking primitive already exists and is already used by the console: the audience preview
  returns `masked_mailbox` (`packages/database/src/kp_database/campaign_service.py:586-588`,
  `_masked_mailbox("jane@corp.example") -> "j***@corp.example"`) via
  `_audience_preview_payload` (`routers.py:543-552`) and is rendered at `console/app.js:2793`.
- The salted mailbox digest exists for exact lookups: `hash_mailbox(mailbox, salt)`
  (`packages/database/src/kp_database/privacy.py:64-73`), salt from
  `settings.require_recipient_hash_salt()` (`apps/operator-api/src/kp_operator_api/config.py:285`),
  indexed column `Recipient.mailbox_sha256` (`packages/database/src/kp_database/models.py:573`).
  `display_name` and `mailbox` are `CipherText` columns (`models.py:572-575`), so no server-side
  substring search over them is possible or desirable.

### Proposed UX

- Every picker and table shows a **label**, not a reference:
  `Jane Doe · j***@corp.example · Finance · active` for `view_named` holders;
  `j***@corp.example · Finance · active` when `display_name` is empty;
  unchanged `Finance · 3f2a9c1e · active` for callers who only hold `MANAGE_RECIPIENTS`
  (the `campaign_operator`), since that capability was never meant to reveal names.
- **Find a recipient** box above each picker: (a) client-side filter of the already-loaded
  bounded page (≤500 rows, `:2258`, `:4293`, `:5304`) on the label text; (b) an "exact mailbox"
  lookup that sends the full address to the server, which hashes it with the salt and returns
  the single matching row. No wildcard, no prefix, no LIKE.
- Recipient outcomes (`:699-727`) and the ledger drill-down (`:4258`) show the same label.

### Where it lands / API change

| Change | Location |
|---|---|
| `list_recipients` gains `display_label` shaping: when `principal.can(VIEW_NAMED_RESULTS)`, add `display_name` and `masked_mailbox` (reuse `_masked_mailbox`) to each item; otherwise the item shape is unchanged. Add `?mailbox=` query param: normalise with `_normalize_mailbox`, compute `hash_mailbox`, filter `Recipient.mailbox_sha256 == digest`, return ≤1 row. | `routers.py:2760-2786` |
| `campaign_recipient_results` adds `display_name` + `masked_mailbox` (already `VIEW_NAMED_RESULTS`-only). Update the docstring at `:2238-2244` to say identification is intentional **for this capability**. | `routers.py:2295-2343` |
| A single `recipientLabel(r)` helper replaces every `.slice(0, 8)` site listed above; adds the filter input to `makeMulti` pickers. | `console-js/app.js` (bundle sites `:713, :2618, :2685, :4298, :5678-5701`) |
| Move `_masked_mailbox` to `kp_database.privacy` (next to `hash_mailbox`) so both API and the campaign service import one definition. | `campaign_service.py:586-588` |
| Inventory test: no new route (query-param only). | — |

**Gate interaction: none.** The frozen manifest hashes `recipient_id` + `mailbox_sha256`
(`campaign_service.py:580-583`), not labels. Capability boundaries are unchanged — names appear
only for the capability literally named `view_named:results`. Recommended extra: audit one
`recipients.exact_lookup` event per exact-mailbox query (actor, digest prefix, hit/miss) so the
privacy approver can see who looked up whom.

---

## 2. Rendered HTML preview + "proof send" to my test mailbox (U2, closes S9)

### Current gap

- `POST /templates/preview` and `GET /templates/{id}/preview` render `safe_html` but return it as
  inert JSON with `html_execution: False`
  (`apps/operator-api/src/kp_operator_api/content_library.py:120-177`, comment at `:157-158`).
- The console explicitly refuses to render it: `showRenderedTemplatePreview` shows the plain-text
  fallback in a "desktop"/"mobile" frame that is just `<pre>` (`console/app.js:4393-4410`) and
  says so (`:4426-4430`). An approver can therefore only read plain text — S9's blind spot.
- Ad-hoc test send is a hard stub that audits `campaign.test-send.blocked` and raises
  (`routers.py:1876-1897`); `can_test_send` is pinned `False` (`:1337`). The only way to see the
  real message in a mailbox is the canary, which requires a frozen audience, approvals and
  `SCHEDULE_CAMPAIGN` (`:1568-1750`).
- Console CSP: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self';
  img-src 'self'` (`main.py:738`), stamped on `/console*` (`main.py:642-643`);
  `X-Frame-Options: DENY` on every response (`main.py:640`).

### Proposed UX

**2a. In-console HTML preview (sandboxed `srcdoc`).**

- In `showRenderedTemplatePreview`, add an **"HTML"** mode next to Desktop/Mobile/Plain
  (`console/app.js:4413`). It renders
  `<iframe sandbox="" referrerpolicy="no-referrer" srcdoc="…rendered.safe_html…">` inside the
  existing `.preview-frame`.
  - `sandbox=""` (no `allow-scripts`, no `allow-same-origin`, no `allow-forms`, no
    `allow-popups`): the document is opaque-origin, cannot run script, cannot submit forms,
    cannot navigate the top frame.
  - An `about:srcdoc` document **inherits the embedding document's CSP**, so inside the frame
    `script-src 'self'` blocks inline script and `img-src 'self'` blocks remote images — no
    tracking beacons fire from a preview. The srcdoc navigation itself is not a fetch and is
    not subject to `frame-src`; the browser smoke test (below) is the acceptance check, and if
    a browser does block it the fallback is adding `frame-src 'self'` to `_CONSOLE_CSP`, which
    the CSP contract test tolerates (it only forbids `'unsafe-inline'`/`'unsafe-eval'`).
  - Because `style-src 'self'` is inherited, inline `style=` attributes and `<style>` blocks in
    the lure do **not** apply. The preview is therefore "structure, text, links" fidelity, which
    is what the approver needs for S9 (what does it say, where do the links go); pixel fidelity
    comes from 2b.
  - Every `href` in the frame is shown in a **link table** under the frame (extracted client-side
    from the same string with `DOMParser`, never by executing it), so the approver reads the
    actual destinations without hovering.
- `html_execution: False` in the API contract (`content_library.py:176`) should be renamed
  `html_execution: "sandboxed_srcdoc"` only after the console change ships, together with an
  updated comment at `:121-126`.

**2b. Proof send — "Send this draft to my test mailbox".**

- A per-campaign action available in `DRAFT` and `PENDING_APPROVAL` for anyone holding
  `CREATE_CAMPAIGN`, `APPROVE_SECURITY` or `APPROVE_PRIVACY`. Target: exactly one recipient that
  is `is_test_account = True`, `ACTIVE`, not deleted — the same server-designated set the canary
  uses (`campaign_service.py:321-342`). The picker is the Section 1 labelled picker filtered to
  test accounts, so "my test mailbox" is chosen by name.
- The subject is prefixed `[PROOF] ` so a proof can never be mistaken for a real lure in the
  test mailbox; the body is byte-identical to the rendered lure.
- Audited as `campaign.proof-send` with campaign id, recipient id, template hash and actor.

### Where it lands / API change

| Change | Location |
|---|---|
| New `POST /campaigns/{id}/proof-send` `{recipient_id}` — `require_any_capability(CREATE_CAMPAIGN, APPROVE_SECURITY, APPROVE_PRIVACY)`; state ∈ {DRAFT, PENDING_APPROVAL}; recipient must be `is_test_account`/`ACTIVE`; emergency stop checked via `_system_safety_state(shared_lock=True)` (`routers.py:1594-1605` pattern); enqueue a `deliver` outbox message with `job_type: "proof_send"` (mirrors the `acs_delivery_receipt` job-type dispatch at `apps/workers/src/kp_workers/jobs.py:1276-1278`). Replaces the stub at `routers.py:1876-1897`. | `routers.py` |
| Worker `process_proof_send`: re-checks emergency stop (`jobs.py:1297-1310`), campaign state, template hash == `campaign.manifest_hash` (`:1339-1340`), renders with the **same renderer and same synthetic tracking context as the preview** (`content_library.py:127-141`), sends through the same sender adapter and the same `KP_ALLOWED_RECIPIENT_DOMAINS` / sending-domain checks. It creates **no** `RecipientAssignment`, **no** tracking token and **no** canary evidence. | `jobs.py` |
| `can_proof_send` flag added to `_campaign_action_flags` (`routers.py:1301-1348`); `can_test_send` stays `False`. | `routers.py:1234` |
| Console: "Send proof to test mailbox" button beside "Review campaign" (`console/app.js:3080-3086`), one confirm dialog listing recipient label + subject. | `console-js/app.js` `views.campaigns` |
| Approval dialog (`console/app.js:3164-3178`) gains a "Preview HTML" button that opens 2a for the campaign's current template, so the approver never records a decision without seeing the message. | `console-js/app.js:3015` (`approvalAct`) |
| Inventory test: add `POST /campaigns/{id}/proof-send`. | `tests/test_route_authorization_inventory.py` |
| Browser smoke: extend `apps/operator-ui/tests/chart-smoke.mjs` (or a sibling) to assert the srcdoc frame renders and that an `<img src="https://…">` inside it does **not** load. | `apps/operator-ui/tests/` |

**Gate interaction: interacts, preserved.** The canary→publish gate is untouched: proof sends
never create assignments or evidence, so `campaign_launch_gate_error`, `canary_manifest_hash` and
`canary_evidence_hash` (`jobs.py:1007-1130`) cannot be satisfied or polluted by a proof. The
emergency stop is honoured at enqueue and at send. Recipient policy is honoured because only
server-designated test accounts are eligible — the same designation that gates the canary
(`campaign_service.py:331`). This design deliberately does **not** reuse the `test_send: True`
payload flag: DEL-002 is removing the template-approval and two-person skips that flag enables
(`jobs.py:1337`, `:1345`), and a proof send needs neither skip because it is not a delivery
against the audience. If DEL-002 lands first, nothing here changes.

---

## 3. Emergency stop reachable on every screen (U3)

### Current gap

- The global stop is a route-level capability: `POST /kill-switch`, `POST /kill-switch/reset`,
  `GET /kill-switch` all require `USE_KILL_SWITCH` (`routers.py:4074`, `:4184`, `:4223`), and
  `campaign_operator` holds it (`rbac.py:141`).
- But the only **global** engage/reset control in the console lives in `views.audit`
  (`console/app.js:6979-7046`, buttons at `:7007-7038`), and that view is hidden unless
  `VIEW_AUDIT` (`NAV_CAPABILITIES.audit`, `:954`) — which `campaign_operator` lacks. The
  operator most likely to be watching a live send cannot reach the button.
- The readiness checklist tells them "Reset it from Audit" and deep-links to `audit`
  (`:2196-2197`), and Settings says "Use the audited global emergency stop in Audit" (`:7164`).
  Both links dead-end for the operator role.
- Only the **scoped** per-campaign kill switch is on the campaigns table (`:3087-3105`), and only
  while the campaign is `scheduled|sending|active`.

### Proposed UX

- A persistent **Emergency stop** control in the sidebar footer of the shell (`shell()`,
  `console/app.js:965-1010`; source `console-js/app.js:891`), rendered iff
  `hasCapability(USE_KILL_SWITCH)`:
  - a state pill (`ok` "Delivery enabled · gen N" / `down` "GLOBAL STOP ENGAGED · gen N"),
    refreshed with the view's existing refresh cadence via `GET /kill-switch`;
  - one red button **"STOP all delivery"** (or **"Reset global stop"** when engaged) that runs
    the exact flow now in Audit: reason prompt → danger confirm → `POST /kill-switch`
    `{confirm:true, reason}` (`:7011-7031`). This is the one control that keeps a **typed
    confirmation** (`STOP` / `RESET`), see Section 8.
- Readiness `destination` for the `kill` check (`:2197`) and the Settings copy (`:7164`) point
  to the sidebar control instead of Audit.
- Audit keeps its history (engaged-by/reason lines `:7043-7045`) but its button becomes the same
  shared component, not a second implementation.
- Users **without** `USE_KILL_SWITCH` (both approvers) see a read-only pill only if they hold
  `VIEW_AGGREGATE`; a small `GET /kill-switch/state` read is **not** proposed — instead the
  existing readiness context already surfaces "engaged" through `campaignReadinessContext`
  (`:2087`) only for kill-switch holders, and that stays as is. The approvers' stop control is
  per-campaign `Recall` (`STOP_CAMPAIGN`, `routers.py:1900-1957`), which they already have.

### Where it lands / API change

| Change | Location |
|---|---|
| `emergencyStopControl()` component + poll; used by `shell()` and `views.audit`. | `console-js/app.js:891` (shell), `:6619` (audit) |
| Readiness copy/destination. | `console-js/app.js:2052` (`readinessForCampaign`, `kill` entry) |
| No endpoint change; no capability change. | — |

**Gate interaction: none.** Same endpoint, same `USE_KILL_SWITCH`, same server-side
`confirm=true` + non-empty reason requirement (`routers.py:4082-4092`, `:4192-4196`), same
persistent `system_safety_state` generation counter. The change is purely where the button is.

---

## 4. Reusability: clone campaign, re-sign RoE prefilled, remembered defaults (U4)

### Current gap

- Every campaign is typed from scratch in the create form (`console/app.js:2457-2569`): sender,
  display name, training domain, max recipients, pattern, template, lesson, window.
  `POST /campaigns` (`routers.py:768-851`) always creates a fresh `DRAFT` with an empty audience
  (`:821`, `:835`). Audience selectors must be re-entered in the audience editor (`:2663-2699`).
- The RoE sign dialog (`:3666-3695`) prefills only the target-domain list (`:3675`); authorizing
  party, terms and window are retyped for each engagement window.
- Program planner already embodies the right clone semantics — "separate draft with an unfrozen
  audience, no copied approvals and no Rules-of-Engagement binding" (`:3263-3266`) — but only as
  a cadence of a *scheduled* source campaign, not as a one-off "make another like this".
- Template clone exists (`POST /templates/{id}/clone`, `:4533`) and is a good precedent.

### Proposed UX

- **"New campaign like this"** action on every campaign row (any state). Phase 1 is
  **client-side only**: it scrolls to the create form and prefills title `"<title> (copy)"`,
  sender, display name, training domain, max recipients, pattern, template, lesson, and leaves
  the window blank (the API rejects `schedule_end <= now`, `routers.py:1637-1638`, so a copied
  window would only mislead). After `POST /campaigns` succeeds, the console immediately
  `PUT`s the source campaign's audience **configuration** (from `GET /campaigns/{src}/audience`,
  `routers.py:998`) onto the new draft, then opens the audience editor at "Save & preview" so the
  operator sees the masked preview and freezes deliberately.
  Everything that must reset, resets by construction: state is `DRAFT`, there are no
  approvals, no launch gate, no `roe_id`, and the frozen manifest must be rebuilt from a new
  preview hash (`routers.py:1083-1125`).
- **"Re-sign for a new window"** on each RoE row (`:3761-3768`): opens `signRoe` with
  authorizing party, terms and target domains prefilled from that row and the window fields
  empty (default suggestion: same length, starting tomorrow 09:00 local). The new RoE is a new
  signature (v2 binds terms hash, party, domains, full window, signer, time —
  `sending_domains_roe.py:291-300`); the old one is untouched unless the operator also chooses
  "revoke previous".
- **Remembered defaults without storage**: the create form prefills sender, display name,
  training domain and max recipients from the **most recent campaign in the already-loaded list**
  (`:2248`). No `localStorage`, nothing to clear, nothing that can go stale across browsers.
- Optional Phase 2 (only if the two operators want an audit line for it): server-side
  `POST /campaigns/{id}/clone` recording `campaign.clone {cloned_from}`; same reset semantics.

### Where it lands / API change

| Change | Location |
|---|---|
| Prefill helpers + "New campaign like this" button; post-create audience PUT. | `console-js/app.js:2208` (`views.campaigns`) |
| "Re-sign for a new window" per RoE row; `signRoe(prefill)` signature. | `console-js/app.js:3352` (`views.sending`), `:3508` (`signRoe`) |
| No endpoint change in Phase 1. Phase 2 (optional) adds one route + inventory entry. | — |

**Gate interaction: none.** Cloning re-enters the front of the pipeline: pattern/template/lesson
approval re-validated at create (`routers.py:775-811`), audience must be previewed and frozen
again, submit re-binds a launch review, approvals are per launch-manifest hash
(`routers.py:1508-1516`), RoE coverage re-checked at schedule (`:1639-1685`). Re-signing an RoE
still requires `SIGN_ROE` and DNS-verified active domains (`sending_domains_roe.py:303+`).

---

## 5. Approver "needs my decision" queue + dashboard count (U5, pairs with AUT-002)

### Current gap

- Approval actions exist only as per-row buttons buried in the campaigns table
  (`console/app.js:3039-3046`), driven by server flags `can_approve_security` /
  `can_approve_privacy` (`routers.py:1315-1316`; `can_review` at `:1264-1273` already excludes
  the creator and already-decided lanes).
- The Dashboard (`:2028-2044`) loads status, campaigns and an audit verify but shows no
  "waiting on you" count. An approver logging in has to scan the whole table.
- The approval dialog copy (`:3174`) and the campaigns banner (`:2244`) say "one independent
  operator with both capabilities may complete both" — which is exactly what AUT-002 removes.

### Proposed UX

- **Dashboard card "Needs my decision"**: count + list of campaigns where
  `can_approve_security || can_approve_privacy`, each row showing title, which lane(s) are open
  for *me*, submitter, audience size (frozen version), window, and two buttons: **Preview HTML**
  (Section 2a) and **Decide** (opens the existing `approvalAct` dialog). Computed client-side
  from `/campaigns` — zero backend change.
- **Sidebar badge** on "Campaigns" with the same count, so the number is visible from every
  screen.
- The queue never offers a combined "approve both" action. Each lane is its own audited
  decision, as today (`routers.py:1518-1548`).
- **After AUT-002 lands**, `_campaign_action_flags` must additionally return
  `can_approve_<lane> = False` when this principal already approved the *other* lane on the same
  launch manifest, so the queue never shows a decision the server will reject; and the copy at
  `:2244` / `:3174` changes to "two different people must approve".

### Where it lands / API change

| Change | Location |
|---|---|
| Dashboard card + sidebar badge (client-only). | `console-js/app.js:1966` (`views.dashboard`), `:891` (`shell`) |
| Post-AUT-002: flag tightening. | `routers.py:1264-1273` (`can_review`) |
| Post-AUT-002: copy at `:2244`, `:3174`. | `console-js/app.js:2208`, `:3015` |
| No endpoint change. | — |

**Gate interaction: interacts, preserved.** The queue is a projection of server-computed flags;
`approve_campaign` still enforces state, frozen audience, launch gate, self-approval
(`routers.py:1491-1516`) and — once AUT-002 lands — distinct approvers. Making the queue
accurate after AUT-002 is a flag change, not a gate change.

---

## 6. Send-time spread / business hours / stagger (U6)

### Current gap

- Full publication queues every batch with one `available_at = max(schedule_start, now)`
  (`routers.py:1846`), passed through `_publish_delivery_batches` (`:1412-1475`, param `:1424`,
  enqueue `:1464-1470`) into the outbox (`packages/database/src/kp_database/outbox.py:128-144`).
  Batch size is `delivery_batch_size` (default 200, `config.py:149`). With 125 seats that is one
  batch, delivered within minutes of the start.
- The outbox already honours future `available_at` (claim predicate `available_at <= now()`,
  `outbox.py:196`) and already excludes future-dated rows from the "overdue" health metric
  (`outbox.py:274-276`). The scheduling primitive exists; nothing sets it per batch.
- The campaign already carries `timezone` (`models.py:349`, set from the browser at create,
  `console/app.js:2565`).

### Proposed UX

- Create form gains one block under the window fields (`console/app.js:2506-2520`):
  - **Delivery pacing**: `All at start` (default, today's behaviour) / `Spread over 1 h` /
    `4 h` / `1 business day` / `Across the whole window`.
  - **Business hours only** checkbox with `09:00–17:00` and weekday toggles, interpreted in the
    campaign's `timezone`.
  - **Batch size** stays a server setting; the UI shows the derived plan: "125 recipients in 5
    batches of 25, first 09:05 Mon, last 16:40 Tue" from a server-computed preview so the
    number the operator sees is the number the server will use.
- Campaign review (`routers.py:890-928`) and the publish confirm dialog (`:3230-3239`) show the
  same derived plan.

### Where it lands / API change

| Change | Location |
|---|---|
| `Campaign` gains `pacing` (`{"spread_seconds": int, "business_hours": {"start": "09:00", "end": "17:00", "weekdays": [1..5]} | null}`), one Alembic revision. | `models.py:340-370` |
| `CampaignCreate` accepts `pacing`; `create_campaign` validates spread ≤ window. | `routers.py:768-851` |
| **`pacing` is added to `campaign_launch_review_manifest_hash`** (`campaign_service.py:269-297`) so it is frozen at submit and changing it after approval invalidates the review exactly like changing the window does. | `campaign_service.py:280-296` |
| A pure function `plan_delivery_batches(n_assignments, batch_size, schedule_start, schedule_end, pacing, tz) -> list[datetime]` (unit-tested; clamps every slot to `[max(start, now), schedule_end]`, snaps forward to the next business-hours slot, never emits a slot after `schedule_end`). | new `kp_database/delivery_pacing.py` |
| `_publish_delivery_batches` takes `available_at: float | list[float]` and enqueues batch `i` at `plan[i]`; the canary path (`routers.py:1711-1722`) keeps passing nothing (immediate). | `routers.py:1412-1475`, `:1835-1847` |
| `GET /campaigns/{id}/review` adds `delivery_plan` (list of `{batch, size, available_at}`) for display. | `routers.py:890-928` |
| Publish audit detail adds `first_available_at` / `last_available_at`. | `routers.py:1851-1865` |

**Gate interaction: interacts, preserved.** The manifest is *strengthened* (pacing becomes part
of what the approvers signed). The evidence gate is unchanged: publish still requires
`canary_succeeded` with unexpired evidence at publish time (`routers.py:1784-1797`); a batch
scheduled for later does not re-verify evidence because the worker verifies the launch manifest
and canary hash on every message (`jobs.py:1007-1130`) and publication is a single audited
decision. The emergency stop still cancels every queued assignment regardless of `available_at`
(`routers.py:4113-4131`) and the worker re-checks the stop before every send (`jobs.py:1297`).
Schedule-window expiry is enforced by the clamp and by the worker's state check
(`jobs.py:1311`). Campaign `expires_at = schedule_end` (`routers.py:830`) is unchanged.

---

## 7. Evidence export (U7)

### Current gap

- `GET /campaigns/{id}/report.csv` exists (`routers.py:2353-2377`, `EXPORT_BULK`) but nothing in
  the console calls it; the only campaign download is the analytics funnel CSV
  (`console/app.js:743-754` → `:759-765`). `downloadApiCsv` allow-lists `/analytics/` paths only
  (`:250`), so `report.csv` could not be reached even by URL.
- There is no single artefact that says "this campaign was approved by A and B with these
  rationales, under RoE R, against manifest M, with canary evidence E". The pieces exist as rows:
  `CampaignApproval` (approver, decision, rationale, decided_at, launch_manifest_hash —
  `routers.py:1518-1528`), the RoE (`roe_id`, `terms_hash`, signer, window, domains), the launch
  gate (`review_manifest_hash`, `canary_manifest_hash`, `canary_evidence_hash`, `provider`,
  `provider_config_hash` — `:917-926`, `:1729-1739`, `:1857-1864`), the training binding digest
  (`:864-872`), and the audit events for the campaign object.
- `GET /audit` returns the latest 500 events with no filter (`routers.py:3998-4006`;
  `audit_store.list_events(limit)` at `packages/database/src/kp_database/audit_store.py:222-235`)
  and there is no CSV.
- `EXPORT_BULK` is administrator-only (`rbac.py:163`); `auditor` cannot export anything.

### Proposed UX

- Campaign report modal (`console/app.js:612+`) gets three buttons:
  **Aggregate CSV** (existing funnel), **Report CSV** (`report.csv`, now wired),
  **Evidence bundle** (`evidence.zip`).
- **Evidence bundle** = one zip (stdlib `zipfile`) containing `campaign.json` (campaign fields,
  content manifest hash, audience version/hash, launch gate hashes, training binding, pacing),
  `approvals.json` (both lanes: approver id, decision, rationale, decided_at, manifest hash),
  `roe.json` (id, party, signer, window, domains, terms hash, signature version),
  `audit-events.csv` (every audit event whose `object_id` is the campaign, plus
  `kill-switch.*` events inside the window), `chain-head.json`
  (`audit_store.head_snapshot()`, `audit_store.py:237`), and `manifest.sha256` of all of the
  above. The bundle is **read-only evidence**; it never includes mailboxes or display names
  (recipient rows appear as `recipient_hash` only).
- **Audit view** (`:6979+`) gets a filter bar (object id, action prefix, actor, since/until) and
  a **Download CSV** of the filtered result, bounded at 10 000 rows.

### Where it lands / API change

| Change | Location |
|---|---|
| Console: extend `downloadApiCsv` allow-list to `/campaigns/{uuid}/report.csv`, `/campaigns/{uuid}/evidence.zip`, `/audit.csv`; accept `application/zip` for the bundle (rename to `downloadApiFile`, keep the 5 MB cap). | `console-js/app.js:144` |
| New `GET /campaigns/{id}/evidence.zip` — `EXPORT_BULK`; audits `results.export {kind: "evidence"}`. | `routers.py` next to `:2353` |
| `list_events` gains optional `object_id`, `action_prefix`, `actor`, `since`, `until` (parameterised SQL, same read-only connection). New `GET /audit.csv` + query params on `GET /audit` — `VIEW_AUDIT`. | `audit_store.py:222`, `routers.py:3998` |
| Also audit `results.export` on `report.csv` and the analytics CSVs (today bulk exports leave no trace). | `routers.py:2353`, `analytics_routes.py:707/755/797/845/889` |
| **Decision required:** grant `EXPORT_BULK` to `auditor` (and optionally the two approver roles) in `_ROLE_CAPABILITIES`, or keep it admin-only and accept that the admin account produces evidence. Recommended: `auditor` gets it; approvers do not. This is a role-matrix change and must be reflected in the inventory test fixtures. | `rbac.py:150` |
| Inventory test: two new routes. | `tests/test_route_authorization_inventory.py` |

**Gate interaction: none.** All additions are read-only projections of rows that already exist,
behind the capabilities that already guard them. The audit chain is read through the store's
existing read-only connection; nothing writes to `audit_events` except the DB-owned signer.

---

## 8. Lower-value polish (U8–U11)

### 8a. Right-size confirmations

**Current gap.** 30+ `confirmDialog` sites (`console/app.js:398-424` definition; calls at `:449,
:1521, :1668, :2340, :3088, :3199, :3230, :3358, :3703, :3726, :4771, :4814, :5025, :5120,
:5370, :5534, :5876, :6128, :6412, :6598, :6916, :7018, :7141`). Three flows require a **typed
phrase**: test-account designation `DESIGNATE xxxxxxxx` (`:4991-5019`) *followed by* a second
danger confirm (`:5025-5034`) — three steps; privacy-request deletion `DELETE xxxxxxxx`
(`:5816-5835`); the global stop (`:7011-7025`, reason prompt + confirm). Meanwhile **Recall**
(`:3070-3077`) — which expires queued assignments and revokes tokens (`routers.py:1918-1941`) —
has **no** confirmation at all, and audience-group save reloads the page (`:2654`).

**Proposal.**

| Action | Today | Proposed |
|---|---|---|
| Global stop engage / reset | reason + confirm | reason + **typed `STOP` / `RESET`** (the only typed confirm) |
| Scoped kill switch, Recall | confirm / none | one danger confirm with counts (Recall gains one) |
| Test-account designation | typed phrase + confirm | one danger confirm with reason (server still requires `confirm:true` + reason, `routers.py:2789-2792`) |
| Privacy-request deletion | typed phrase | one danger confirm with reason; the typed UUID prefix adds no protection over a labelled row |
| Queue canary / publish | confirm with detail list | keep (these are the launch decisions) |
| Save group / audience / lesson binding / alert subscriptions / template clone | confirm or reload | no confirm; inline success toast; no `location.reload()` — re-render the affected card |

**Gate interaction: none.** Every typed phrase above is UI-only; the server never sees it. The
server-side `confirm=true` + reason requirements (`routers.py:4082-4092`, `:2789-2792`) are
untouched.

### 8b. Replace env-name fields with selects of verified domains

**Current gap.** The create form's sender field is a free `type=email` input whose help text
cites `KP_SENDING_DOMAINS` (`console/app.js:2464-2473`); training domain is free text
(`:2475-2480`); the domains view repeats the env name (`:3756`). The verified-domain list is
available at `GET /sending-domains` (`sending_domains_roe.py:191-206`) but only for
`VERIFY_DOMAIN`, which `campaign_author` lacks (`rbac.py:122`). The training-domain allowlist
lives in worker/API settings (`config.py:110`, `training_domains`) and is only visible through
the onboarding step for `MANAGE_ROLES` (`:2085`, `:2100`).

**Proposal.**

- Sender = **local-part input + select of active verified domains** (`security-awareness` @
  `[training.corp.example ▾]`). Training domain = **select** from the configured allowlist.
- New read-only `GET /campaigns/options` — `CREATE_CAMPAIGN` — returning
  `{sending_domains: [active verified], training_domains: [allowlist], approval_policy}`; no
  secrets. Alternatively widen `GET /sending-domains` to
  `require_any_capability(VERIFY_DOMAIN, CREATE_CAMPAIGN)`; the dedicated endpoint is preferred
  because it also carries the training list.
- Help text stops naming environment variables; the operator sees "verified domains" and
  "training destinations" and a link to Domains & RoE when the list is empty.

**Gate interaction: none.** The worker still enforces the sending-domain and training-domain
allowlists at send time (`apps/workers/src/kp_workers/config.py:283-285`); the select only
prevents typing something the worker would refuse. Inventory test: one new route.

### 8c. Consolidate the 17-item nav toward the UX-010 grouping

**Current gap.** `NAV` has 17 entries (`console/app.js:919-937`), rendered flat (`:973-982`), with
setup/deployment items first and the daily-use items in the middle.

**Proposal** (interim step toward UX-010's five areas; deep links by `#hash` unchanged,
`NAV_CAPABILITIES` (`:938-956`) unchanged, groups collapse when none of their items is visible):

| Group | Items |
|---|---|
| Home | Dashboard, Help |
| Campaigns | Campaigns, Programs, Patterns, Template review, Training lessons, Domains & RoE |
| People | Recipients, Privacy |
| Reports | Executive trends, Audit |
| System | Setup wizard, Azure deployment, Failed jobs, Settings |

Plus the Section 3 emergency-stop control and the Section 5 badge in the sidebar footer/label.

**Gate interaction: none.** Per-view capability checks (`requireAnyCapability` at each view) are
untouched; grouping is presentation only.

---

## 9. Phasing and priority

Effort: **S** = console-only (`console-js` + rebuild), no API change; **M** = console + one
read-only or narrowly-scoped route + inventory test; **L** = schema/worker change.

### Phase 1 — quick wins (all S; ship as one PR each, in this order)

| # | Item | Effort | Why first |
|---|---|---|---|
| 1 | **§3 Emergency stop in the sidebar** | S | The operator who runs sends cannot currently reach the global stop; pure relocation of an existing, audited control. |
| 2 | **§5 "Needs my decision" card + badge** | S | Client-side projection of server flags; makes the second operator's job obvious. Copy fix follows AUT-002. |
| 3 | **§4 Clone / prefill / re-sign RoE prefilled** | S | Removes the retyping that makes every campaign a chore; zero backend change; all gates re-entered by construction. |
| 4 | §8c nav grouping + §8a confirmation right-sizing (+ the missing Recall confirm) | S | Small, mechanical, and the nav change makes items 1–2 easier to find. |
| 5 | §2a sandboxed HTML preview + link table | S (+ CSP smoke test) | Closes the approver blind spot (S9) with no backend change. |
| 6 | §7 wire `report.csv` (allow-list extension only) | S | Existing endpoint, one line in the allow-list plus a button. |

### Phase 2 — read-only API additions (M)

| # | Item |
|---|---|
| 7 | §1 display labels in `/recipients` and campaign outcomes + exact-mailbox digest lookup |
| 8 | §8b `GET /campaigns/options` + sender/training selects |
| 9 | §7 audit filters + `/audit.csv`; evidence bundle; export audit events; `auditor` gets `EXPORT_BULK` (decision) |

### Phase 3 — behaviour additions (L; each needs its own gate review)

| # | Item | Depends on |
|---|---|---|
| 10 | §2b proof send (`/campaigns/{id}/proof-send` + `process_proof_send`) | DEL-002 should land first or in the same wave so `test_send` semantics are not in flux |
| 11 | §6 delivery pacing (`pacing` column, manifest hash v2, `plan_delivery_batches`, per-batch `available_at`) | none, but bump `campaign_launch_review_manifest_hash` `version` to 2 |

### Cross-cutting acceptance

- `apps/operator-api/tests/test_route_authorization_inventory.py` updated for every new route;
  `test_console_csp_contract.py` still green with `_CONSOLE_CSP` unchanged.
- `node scripts/build-console.mjs` reproduces the committed bundle; `npm run check` passes.
- A browser smoke (extend `apps/operator-ui/tests/chart-smoke.mjs`) covering: sidebar stop
  control visible for a `campaign_operator` session and absent for `security_approver`; the
  srcdoc preview renders and blocks a remote image; the decision card count equals the number of
  rows with an open lane.
- Every PR description restates, per item, the "gate interaction" line from this document.

## 10. Summary of API surface changes

| Route | Capability | Section | Kind |
|---|---|---|---|
| `GET /recipients?mailbox=` (+ `display_name`, `masked_mailbox` fields) | existing | 1 | shape/query |
| `GET /campaigns/{id}/recipients` (+ fields) | existing `VIEW_NAMED_RESULTS` | 1 | shape |
| `POST /campaigns/{id}/proof-send` | `CREATE_CAMPAIGN` \| `APPROVE_*` | 2b | new (replaces stub) |
| `GET /campaigns/{id}/review` (+ `delivery_plan`) | existing | 6 | shape |
| `POST /campaigns` (+ `pacing`) | existing | 6 | shape |
| `GET /campaigns/{id}/evidence.zip` | `EXPORT_BULK` | 7 | new |
| `GET /audit?object_id&action_prefix&actor&since&until`, `GET /audit.csv` | `VIEW_AUDIT` | 7 | query/new |
| `GET /campaigns/options` | `CREATE_CAMPAIGN` | 8b | new |
| `_ROLE_CAPABILITIES[AUDITOR] += EXPORT_BULK` | — | 7 | role matrix (decision) |

No existing capability requirement is loosened; no gate endpoint (`/schedule`, `/publish`,
`/approvals/*`, `/kill-switch*`, `/audience/freeze`, `/roe`) changes its checks.
