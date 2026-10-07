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

1. **Create** — pick an approved lure pattern and one approved training lesson.
2. **Freeze the audience** — lock the exact list of recipients so what was
   reviewed is exactly what gets sent.
3. **Approve** — this depends on your deployment's approval mode:
   - **Two-person mode** (`enforce`; always the case in Azure): the person who
     created the campaign cannot approve it. A single independent reviewer with
     both capabilities may complete the security and privacy approvals, or two
     reviewers may split them.
   - **Single-operator mode** (`single-operator`; the supported small-team
     posture, and what a default on-prem install runs): there is no second
     approver. Submitting the campaign for review approves it, and you may
     approve the threat pattern and the AI-generated draft you requested
     yourself. Every such decision is still recorded in the audit trail, marked
     `self_approved` / `self_reviewed`, so who did each step is never lost.
   Both modes keep everything below this line unchanged — the canary gate, the
   Rules-of-Engagement boundary, and the audit trail apply identically.
4. **Run the canary** — send only to a small group of internal test accounts and
   wait for the mail provider to confirm it actually went out.
5. **Publish** — send to the full audience. This button stays disabled until the
   canary evidence is current.

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
