# W2-05 — Guided campaign setup and accessibility

Implementation record: 2026-11-06. Base checkout: `cf659d5`.

The changes were subsequently carried forward to current `main` at `fb27305`
and integrated with retention-hold controls. The integrated browser suite passed
13 tests. Current evidence and external-gate status are recorded in
[remaining remediation](../REMAINING-REMEDIATION-2026-11-06.md); the checks below
describe the initial UX qualification on the original controller checkout.

The campaign setup now presents one step at a time in the required order:
Select domain → Sign RoE → Upload/review/confirm recipients → Choose/edit
email → Approve → Send → Monitor. The progress navigation exposes the current
step with `aria-current="step"`, names available steps, and leaves future steps
unavailable until their prerequisite data exists. Back navigation changes the
visible panel without rebuilding its forms. Completing an action focuses the
next step heading and announces the new step.

Email wording, pasted recipient rows and campaign details survive internal
navigation and redraws in memory. Recipient rows and email wording are not added
to browser storage. Selecting a different domain starts a new setup scope;
selecting another signed authorization invalidates the saved roster and email
review. Loading a different library email replaces the email draft.

Field errors appear next to their controls and in a focused summary with links
to the affected fields. Required campaign fields and invalid delivery windows
are checked before final review. CSV row errors use plain language. A recipient
preview or email preview that finishes after its input changes cannot enable
confirmation or approval of that stale input. The final approval dialog shows
the reviewed email subject, sender, roster and current recipient count, domain,
signed authorization party/signer/dates, training lesson/hostname and delivery
window with timezone. Approval and Send remain separate actions. Server-side
authorization, policy and exact-review checks remain authoritative.

The layout uses native form controls, visible keyboard focus, explicit field
labels and descriptions, status announcements, text indicators for progress,
and controls at least 44 pixels high within the campaign steps. The 320-pixel
browser scenario checks that the page does not overflow horizontally. Required
training and delivery fields are visible in a labelled fieldset.

## Verification

- Production console bundle rebuilt with `npm run build`; syntax check passes.
- **12/12 isolated Chromium browser tests passed**, including the whole-roster
  flow at 1280, 768 and 320 pixels; keyboard focus/error recovery; Back navigation;
  preserved campaign details after email changes; final review/cancellation;
  changed-CSV and changed-email response races; throttled send handling; and
  existing Settings, library and live-refresh checks.
- **58/58 focused Python checks passed**: console asset budget, accessibility
  shell, CSP, capability controls, behavioral smoke, existing usability wiring,
  bundle drift, reviewed-direct sends, recipient confirmation and distinct-person
  approvals.
- WCAG 2.1 A/AA axe scans passed with **zero reported violations** at the domain
  error, recipients, email editor, approval error, approval, approval dialog and
  send states. JSON axe results are attached to the browser report. These scans
  exclude the opaque-origin sandboxed email iframe's contents; its accessible
  title and unchanged empty sandbox are separately asserted. Email/training
  content accessibility requires separate review.
- Desktop and narrow-screen approval screenshots and the narrow-screen review
  dialog were visually inspected.

Final browser evidence is retained under
`data/qualification/console-smoke/c4b1ea7a-ad41-46d7-ae46-216a434e7346/`, including
`report/index.html`, screenshots and attached axe JSON. A source-hash manifest is
retained at `data/qualification/campaign-ux-20261106/source-manifest.json`.
Evidence records the local working tree, not a final release image or deployment.

The original `.venv` has a missing Python target and lacks application packages;
the configured external Playwright browser binary is also absent. Both were
preserved. Qualification used a separate lockfile-based Python 3.13 environment
and Chromium installation under `/private/tmp/kp-campaign-ux-20261106-XucAKt/`.
The isolated browser configuration now accepts `KP_CONSOLE_CI_PYTHON` for this
purpose while retaining its normal `.venv/bin/python` default. Reproduction in
this session:

```sh
cd apps/operator-ui
KP_CONSOLE_CI_PYTHON=/private/tmp/kp-campaign-ux-20261106-XucAKt/venv/bin/python \
PLAYWRIGHT_BROWSERS_PATH=/private/tmp/kp-campaign-ux-20261106-XucAKt/browsers \
PLAYWRIGHT_SKIP_BROWSER_GC=1 npm run test:console-smoke
```

## Acceptance still open

W2-05's code portion is implemented; acceptance remains open. For current
on-prem readiness, use the existing [D6 script](../D6-HUMAN-ACCEPTANCE-SCRIPT.md):
one human driver who did not build the software completes the journey unaided,
including recovering from validation errors and reviewing the exact
authorization, recipients, message and training before approval. Record the
build identity, operator observations, blockers and disposition. The original
handoff's two independent usability trials are a stronger pilot criterion;
they do not require two production identities or change the configured campaign
approval policy. A second trial adds evidence about usability across people;
neither WCAG nor the single-operator deployment requires a second approver.

Manual WCAG review must cover keyboard order and focus visibility, screen-reader
labels/error announcements, preview-frame entry/exit, zoom/reflow, contrast and
the recipient email/training content. Run the live browser/axe lane on that
staging build as well. Synthetic browser results are not human acceptance,
provider delivery proof, load/soak qualification or a production GO.

W5-04 now has the [tenant preservation hold implementation](RETENTION-HOLDS-W5-04.md).
W2-04 still requires current-source staging evidence. W5-01's real-Redis component
soak passed separately; this UI work does not qualify a full deployed workload.
