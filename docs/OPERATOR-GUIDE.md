# Operator Guide

Plain-language guide for the people who run Kingphisher-Phoenix day to day. This
is the task-oriented companion to the engineering `RUNBOOK.md` — start here, and
only reach for the runbook when you need to troubleshoot or recover.

## Console credentials

Retrieve the on-prem console password privately from the protected deployment
`.env` (`KP_CONSOLE_PASSWORD`), or from your operator's established private
credential channel. Keep actual passwords out of handoffs, screenshots, issue
bodies and repository files. Published historical credentials require rotation;
redacting the current documents does not remove them from older commits.

Coordinate rotation outside an active acceptance run. The deployment operator
can use the existing validated, atomic `set_console_password` helper in
`kp_operator_api.console.env_store` against the deployment's `.env`, then check
that a new sign-in succeeds and the previous password fails. Share the new value
privately with the driver. Password rotation does not invalidate already-issued
sessions; session-signing-key rotation is a separate coordinated operation.

For the current `.105` build, the user's October 8 instruction defers password
rotation until they sign off on the build as fully completed and human ready.
Do not rotate it before that sign-off or treat rotation as a blocker to the
human trial. Continue to retrieve the existing credential privately.

## What this tool does

Kingphisher-Phoenix sends **simulated** phishing email so your organization can
practice spotting it — and takes people who click through to a short training
lesson. It never captures real passwords, and it never sends anything that is not
an approved, simulated message.

Every send is gated by deterministic safety rules, not by an AI model: who may be
emailed, what the message may contain, and when it may go out are all enforced
in code and recorded in an audit trail.

## Two ways to run it — you choose at deploy time

Both are first-class and fully supported. Pick the one that fits your team.

**On your own hardware (on-prem).**
The whole platform runs on a machine you control (Docker under the hood). You
edit settings in the console, and test email stays local in Mailpit (a built-in
pretend inbox) until you connect a real mail relay. Best for small teams that
want to own their data and keep everything internal.

**In Microsoft Azure (managed).**
The platform runs in Microsoft's cloud. Configuration lives in Azure and is
edited through the reviewed deployment workflow, not the console. Azure always
enforces two-person approval and uses Azure Communication Services Email. Best
for teams that already run in Azure and want managed infrastructure.

The choice is made during first-run setup and can be revisited later; nothing is
locked in.

## Run your first campaign

1. **Domains & RoE → Verified domains → View authorization** beside your
   domain. Check the recorded authorizing party, approved recipient domains,
   authorized dates and active status. DNS verification alone does not grant
   permission to target recipients. Existing authorization can be reused while
   it remains valid for the campaign dates; you do not sign it again each time.
2. **Recipients → Upload a roster → Download CSV template**. If a saved roster
   is already selected, expand **Upload another roster** below its table first.
   Populate `email`
   (required), `name` and `department` (optional), save as CSV, then upload it.
   Give the roster a distinct name. **Validate roster** reports invalid rows
   and domain coverage; **Confirm validated roster → Confirm roster** saves it.
   The saved roster contains only valid people from that file, including people
   previously imported. Select **Review saved recipients** to inspect it or
   **Choose an email for this roster** to continue. The **Viewing recipient
   roster** selector separates each saved roster from all-imports history.
3. **Template review → Choose an email → Safe preview → Select for current
   campaign**. The same selection button appears on approved library rows.
   Working copy describes the message's origin. Clone and Edit create new
   drafts; use them only to change the message, and approve the copy before
   selecting it. A full name is not required for AI generation. If the email
   uses `{{ recipient.first_name }}`, delivery inserts the optional roster name;
   enter the greeting name you want, for example Erik. A template without a
   name placeholder does not gain personalization automatically.
4. **Campaigns → New campaign**. Select the sending domain and uploaded roster,
   check the email, title and send window, then **Create campaign**. The approved
   after-click page and recipient-page host are supplied. Optional changes are
   under After-click content and Advanced delivery settings.
5. **Campaigns → All campaigns → your campaign row → Confirm recipients**.
   Review the included list, excluded counts and approved domains. The uploaded
   roster is already selected; you do not select each person again. If no test
   recipient is designated, its row offers **Designate test account** before
   confirmation. **Confirm recipients** records the exact audience and launch
   review internally, without separate freeze or lock controls in this path.
   **Edit roster options (optional)** is available only when you want different
   selectors or exclusions. In two-person mode this confirmation requests
   security and privacy approval; the creator cannot supply those approvals.
6. **Send test email**. Confirm the test dialog. The row changes to **Test email
   queued — waiting for delivery confirmation**, then **Test email passed** when
   the server has the required provider evidence. Status refreshes every 30
   seconds. **Send campaign** appears when publication is permitted and sends
   only the reviewed recipient list, excluding the test cohort already sent.
7. **Report** on the campaign row shows delivery and training results and offers
   report CSV and evidence-bundle downloads. **Recall** stops this campaign's
   queued mail and invalidates its tracking links.

Recipient validation checks address format, status, exclusions and authorized
recipient domains. It does not prove a mailbox exists or that a human received
mail. **Collect employee-reported phishing**, under the collapsed optional
Microsoft 365 integration panel in Recipients, reads messages employees reported
as phishing and updates report statistics. It is not recipient validation and
is not required for a CSV campaign.

## Send safety

- **Recipient boundary.** Delivery only ever reaches recipients whose domain a
  current, signed Rules-of-Engagement covers — this is the real authorization
  boundary and it cannot be switched off by configuration. There is also an
  optional recipient-domain allowlist: in two-person / Azure mode an unset
  allowlist fails closed (refuses to send); in single-operator mode an unset
  allowlist admits, because the signed RoE is already the binding control. Off
  the RoE, nothing sends, in any mode.
- **Approval rule.** In two-person mode the campaign creator can never approve
  their own work. In single-operator mode the creator can — every self-approval
  is recorded in the audit trail (`self_approved` / `self_reviewed`). See the
  Approve step above; this is the one place the two modes differ.
- **Kill switch.** An emergency stop that immediately cancels queued mail and
  invalidates already-sent tracking links, company-wide or for one campaign.
  Recall cancels one campaign's pending mail; pause stops future scheduling but
  does not cancel queued mail.

## Sending domains and DNS

Mail only delivers from domains you control, with valid SPF, DKIM, and DMARC
records. Prove control of a domain via DNS, then sign a Rules of Engagement (a
dated, signed permission slip) naming which domains may be targeted. No signed,
unexpired RoE means no send.

## Where to find help

The console's **Help** center has plain-language definitions and step guides. For
detailed operational, troubleshooting, and recovery procedures, see `RUNBOOK.md`.
