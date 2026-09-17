# Operator Guide

Plain-language guide for the people who run Kingphisher-Phoenix day to day. This
is the task-oriented companion to the engineering `RUNBOOK.md` — start here, and
only reach for the runbook when you need to troubleshoot or recover.

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
3. **Approve** — complete the required security and privacy approvals. The
   person who created the campaign cannot approve it; a single independent
   reviewer may complete both approvals.
4. **Run the canary** — send only to a small group of internal test accounts and
   wait for the mail provider to confirm it actually went out.
5. **Publish** — send to the full audience. This button stays disabled until the
   canary evidence is current.

## Send safety

- **Recipient allowlist.** The platform only emails addresses on your approved
  list of domains. Anything off-list is blocked, and if the list is missing it
  refuses to send at all — it fails closed.
- **Two-person rule.** The campaign creator can never approve their own work.
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
