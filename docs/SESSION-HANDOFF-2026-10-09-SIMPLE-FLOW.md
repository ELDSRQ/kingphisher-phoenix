# October 9 — simplified operator campaign flow

The user's latest direction is the primary workflow: **Select domain → Sign
RoE → Upload recipients → Review/confirm recipients → Choose a library example
→ Create and review the campaign email → Approve → Send → Monitor.** No canary,
test-account designation, manual freeze or launch-lock task is required.
Server review snapshots and policy checks happen internally. Preserve earlier
campaigns and their evidence; never reinterpret an earlier test as direct-send
evidence. `AGENTS.md` records this superseding instruction.

## Current deployment

- Branch: `fix/simple-campaign-flow-20261009`, stacked on PR #133;
  [PR #134](https://github.com/ELDSRQ/kingphisher-phoenix/pull/134).
- Last verified controller/worker checkpoint before this documentation followup:
  `bb7e76a3a601b906afbc00dd4db12d8a47c1822c`.
  [Its CI passed all required jobs](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37962825425).
  Later followups change documentation only; use `git rev-parse HEAD` for the
  exact checkout. No uncommitted implementation change remains.
- Worker: `.105`, SSH `builder@192.168.1.105:2222`, repository
  `/home/builder/phishing-awareness-platform`. The retired `.140` is untouched.
- Backend and JavaScript source qualified at `c7f20cf`; the later `54d61b3`
  adds error-text contrast and live-browser pacing. The backend last restarted
  through its existing supervisor at `c7f20cf`. Database head is additive
  `0043_reviewed_direct_campaigns`.
- Console: http://127.0.0.1:8600/console/; Mailpit:
  http://127.0.0.1:8025/; training/tracking: http://127.0.0.1:8001/.
  Current test delivery uses the local SMTP/Mailpit provider. The existing
  `example.com` signed RoE expires December 20, 2026.
- Operator/tracking dependency probes and all ten supervisor worker PID probes
  passed. These probes do not prove worker heartbeat or real-provider delivery.

## Integration status — verified October 9

All implementation changes are committed, pushed and present on the development
worker. **They are not merged into `main`.** The prerequisite chain remains:

| Pull request | Base | Status |
|---|---|---|
| [#132](https://github.com/ELDSRQ/kingphisher-phoenix/pull/132) | `main` | Open, not draft |
| [#133](https://github.com/ELDSRQ/kingphisher-phoenix/pull/133) | `fix/human-readiness-training-20261008` | Open, not draft |
| [#134](https://github.com/ELDSRQ/kingphisher-phoenix/pull/134) | `fix/human-operator-flow-20261009` | Open, draft |

This documentation update performs no merge. Keep branch commits, development
deployment and integration into `main` distinct when reporting readiness. The
current copy/paste resume instructions are in
[NEXT-SESSION-PROMPT.md](NEXT-SESSION-PROMPT.md#current-resume-prompt--october-9).

## Verified engineering evidence

- `c7f20cf`: controller hermetic suite **3,611 passed, 114 deselected, zero
  skips**; log `/private/tmp/kp-simple-flow-hermetic-c7f20cf.log`.
- [Exact-source CI](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37960798658):
  hermetic **3,573 passed, 152 deselected**, PostgreSQL **103 passed, 3,622
  deselected**, Redis **2 passed, 3,723 deselected**, browser **5 passed**;
  lint/types passed. Linux intentionally deselects macOS controller contracts;
  integration gates run separately. PostgreSQL reports two existing SQLAlchemy
  warnings. No skip was counted as a pass.
- Personalized preview PostgreSQL regression passed on the dedicated
  qualification database; `/private/tmp/kp-simple-flow-personalized-preview-pg.log`.
- Live whole-roster trial passed at `c7f20cf`, campaign
  `96603f06-30bb-45ae-9d00-3a2e63eda884`. Two ordinary recipients, zero designated
  test accounts, outsider rejected, exactly one whole-roster send, correct
  named/neutral greetings, click and completed training visible per recipient,
  UI CSV/ZIP exports and recall. The recalled tracking URL returns 404.
  Served JavaScript matched source; ZIP integrity passed. Evidence:
  `data/qualification/human-readiness/simple-flow-1441e40f6bcb4cceb91263486a44da8e/`.
- Existing operator campaign `8a0a7e2a-ebb5-464f-9d0f-9a555be5e838` was never
  written by the guarded engineering trial. It was already scheduled with
  earlier test success when the final trial began. Its **Send** action can send
  remaining reviewed recipients using its existing server-derived permission;
  earlier recipients are not duplicated.
- Initial failed trials and the 13/17 browser sweep remain preserved. They
  exposed missing personalization, escaped greeting syntax, stale-preview
  approval, low-contrast error notifications and insufficient test pacing.
  The failed sent engineering campaign `dd00b468-dfa3-40f4-9270-cdf728542785`
  was recalled after recording the failure. No user campaign was recalled.
- `54d61b3`: five local browser checks passed, including an axe audit of the
  throttled-send error. [Exact-source CI](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/37961970807)
  passed all three required jobs. The final live sweep passed **17/17, zero
  skips**, including all eleven axe views and both desktop/tablet navigation
  checks. Evidence:
  `data/qualification/human-readiness/cd22b981b67b4cea96668cd69aab004d/`.
  Served stylesheet matched the tested source. The earlier 13/17 result is
  retained as a failure, not counted as a pass. Follow-up handoff edits change
  documentation only; the qualified runtime code remains `c7f20cf`/`54d61b3`.

## Human run and remaining work

Use [the current detailed trial](D6-HUMAN-ACCEPTANCE-SCRIPT.md#current-trial-simplified-campaign-flow)
and [the operator guide](OPERATOR-GUIDE.md#run-your-first-campaign). Refresh the
console and open **Campaigns**. **Download CSV template** appears after domain
and signed RoE selection; the browser saves `recipient-roster-template.csv` to
Downloads or the chosen folder. Names are optional. The email editor makes
`[recipient name]` and `[training link]` visible and previews before approval.

**Reply monitoring remains unimplemented.** Employee-reported phishing is a
different metric. The operator has been asked which receiving mailbox and mail
service to use; no answer has arrived. Implement and qualify correlation and
reply ingestion once that information is provided. This is a concrete product
blocker, not an Astra/model reasoning blocker. Do not claim the full requested
build is complete or human acceptance passed.

D6 and manual keyboard/screen-reader acceptance remain open. Production/RSA,
real-provider/cloud, image and recovery gates remain separate. Password
rotation waits for the user's completed-build sign-off. Preserve the untracked
`docs/QA-REVIEW-2026-10-07.md`, the worker's `docker-compose.override.yml`, normal
runtime/data/audit assets, all qualification evidence, and the uniquely named
qualification PostgreSQL/Redis containers. No storage cleanup is authorized.
