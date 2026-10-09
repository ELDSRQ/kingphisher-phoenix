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

Open http://127.0.0.1:8600/console/ and sign in. Click **Campaigns** in the left
navigation. Complete the numbered panels on that page. The primary flow has no
canary, test-account designation, manual freeze, launch lock, or individual
recipient selection. The server records and rechecks your reviewed roster.

1. **Select domain:** choose your verified company domain in **Company domain**,
   then click **Select domain**. For the local trial, select `example.com`.
   **Add or verify a domain** opens DNS verification if yours is missing. The
   optional lookalike generator only suggests domain names; it does not select,
   register, verify or authorize a domain.
2. **Sign RoE:** choose an existing current record under **Saved signed
   authorization**, then **Use signed RoE**, or click **Sign RoE for selected
   domain** and record the domain owner's authorization. Read the signed terms,
   signer, dates and approved-domain notice in this panel. DNS verification alone
   does not authorize sending. This campaign targets the selected domain only;
   all other domains in an uploaded roster are rejected.
3. **Upload, review and confirm recipients:** click **Download CSV template**.
   The blank file is **recipient-roster-template.csv**, saved by your browser to
   **Downloads** or the folder you choose. Open it in a spreadsheet editor; keep
   `email,name,department` as the first row. Add one recipient per row, then save
   as CSV. Email is required; name and department are optional. Upload through
   **Completed recipient CSV**, then **Review uploaded recipients**. Inspect
   the masked recipient table, counts and rejected row numbers. Click **Confirm
   validated recipients** to accept the valid list. **Recipients confirmed**
   shows this upload only; past imports are not automatically added. The whole
   confirmed roster is included without a second individual-selection task.
4. **Select an email from the library:** choose **Library email**, then **Use
   this email as a starting point**. The library supplies example wording for
   the fake campaign email you create next.
5. **Create fake email for review:** edit **Email subject** and **Email body**,
   then click **Create fake email for review**. Read **Email preview**. The
   `[recipient name]` in the body uses the uploaded name, or “colleague” when
   blank; the preview uses a sample name. `[training link]` becomes each
   recipient's training link. A full name is not required. Editing again creates a newly
   reviewable copy rather than changing an already approved email.
6. **Approve:** enter **Campaign name**, review **From email** and **From display
   name**. The collapsed **Delivery window and after-click training page** holds
   the configured training hostname, lesson and delivery dates; expand it to
   inspect or change them. Dates must fit the signed RoE. Click **Approve
   campaign**, read the confirmation, then **Approve**. This single-operator
   deployment records your approval immediately. Deployments that enforce
   independent review still require their authorized reviewers.
7. **Send:** under **Campaigns and results**, find the campaign by its name.
   Click **Send**, read the confirmation, then **Send** in the dialog. The
   button disappears after successful queueing and status becomes scheduled
   or active. A queue acknowledgement is not confirmed mailbox delivery.
   A visible error leaves the action available for an explicit retry; requests
   are not automatically resubmitted.
8. **Monitor:** click **Open dashboard** on that campaign. **Monitor recipients**
   selects that campaign and shows delivery state, observed clicks, confirmed
   interaction, employee reports and training by masked recipient. Use **Refresh
   recipient results** for fresh data. **Replies are currently unavailable**:
   reply ingestion has not been built/configured. Employee reports are separate
   from replies. **Report and exports** opens results and download actions.
   **Stop this campaign** stops future deliveries and disables its tracking links.

For an unsent campaign created in the earlier workflow, use **Review current
recipients and approve** on its row. Inspect its saved email, authorized domains
and current recipient list, then **Approve reviewed list**. This explicitly
moves that unsent campaign to the simplified flow; sent campaigns retain their
original history and evidence. Engineering validation does not send your saved
campaigns.

For a full local evaluation, use the concrete checks and failure cases in
[D6 human acceptance](D6-HUMAN-ACCEPTANCE-SCRIPT.md#current-trial-simplified-campaign-flow).

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
