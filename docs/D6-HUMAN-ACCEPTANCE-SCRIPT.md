# D6 — Human acceptance run (on-prem)

## Current run: October 9 operator findings

**D6 remains open.** The October 9 walkthrough found unclear authorization
inspection, no downloadable CSV template, ambiguous roster history and mailbox
polling, undiscoverable email selection, unnecessary separate audience/review
controls, and a test button that did not advance. Record this as a failed human
attempt. Passing implementation tests does not turn that attempt into a pass.

Use the updated [Operator Guide](OPERATOR-GUIDE.md#run-your-first-campaign)
for the revised controls. The repair is on `fix/human-operator-flow-20261009`;
source/deployment validation is recorded in the QA remediation plan. Earlier
instructions below refer to superseded controls.

Before the trial, open the console at http://127.0.0.1:8600/console/ and Mailpit
at http://127.0.0.1:8025/. Recipient links use http://127.0.0.1:8001/. Refresh the
console to load the repaired UI. Use the existing password privately; per the
user's instruction, rotation waits until their completed-build sign-off.

The observer should check these concrete tasks without coaching a formal
unassisted driver:

1. In **Domains & RoE**, find `example.com` in **Verified domains** and use
   **View authorization** on that row. Identify who authorized it, the approved
   recipient domains, dates and active status. Confirm dates cover the intended
   campaign; do not infer authorization from DNS verification alone.
2. In **Recipients**, open **Upload a roster**. If a saved roster is already
   selected, expand **Upload another roster** below the recipient table instead.
   Download the CSV template. Fill it with
   two clearly synthetic `example.com` recipients, save as CSV, and upload it
   with a distinct roster name. Validate and confirm the roster. Names and
   departments are optional. Inspect **Review saved recipients**; verify this
   saved roster is selected and past imports are absent. Identify which account
   should receive the first test email.
3. Use **Choose an email for this roster**. Preview an approved message and
   select **Select for current campaign** inside the preview. Confirm that the
   campaign form retains both the chosen email and uploaded roster.
4. Create a campaign with a unique title and newly valid dates, within the RoE.
   Find its row under **All campaigns**, then **Confirm recipients**. Identify
   included/excluded counts and allowed domains. If needed, designate only the
   synthetic canary using its row's test-account button, then reopen confirmation.
   Confirm the validated list. No individual reselection, separate freeze or
   launch-lock task is required in this path.
5. Use **Send test email** and its confirmation. Observe queued status, the
   captured canary message and eventual server-confirmed success. Use **Send
   campaign** when available and verify the other synthetic recipient's message.
6. Follow the participant's captured link and complete training. Open **Report**
   on this campaign's row, observe results, download the report CSV and evidence
   bundle, and find its audit actions under **More → Audit**.
7. **Recall** only this trial campaign. Retain records, captured mail, exports
   and observations. Record completion unaided / hesitation / needed help /
   blocked at every task. Record exact wording and screenshots before fixes.

For a guided functional evaluation, use these observable checks. Keep the
unassisted D6 driver separate from a coached run.

| Task | Exact place to look and expected result |
| --- | --- |
| Authorization captured | **Domains & RoE → Verified domains → example.com → View authorization** opens the saved record. Look for **Status: Active**, the authorizing party, signer, dates, terms and `example.com` in approved recipient domains. Close the dialog. |
| CSV saved correctly | In **Recipients**, download the template and fill two distinct synthetic addresses under `email`; optional greeting names go under `name`. After validation and confirmation, **Review saved recipients** opens your named roster. Its table contains those two records, with **Active · domain authorized; mailbox existence unverified**. Earlier rosters appear only if you choose them in **Viewing recipient roster**. |
| Test recipient eligible | On your synthetic canary's row select **Designate test account**. Enter a non-personal audit reason, type the exact `DESIGNATE …` phrase printed by the dialog, select **Review designation**, then confirm **Designate test account**. The row must show **Server-designated test account**. Do this before confirming campaign recipients. |
| Email actually selected | **Choose an email for this roster → Template review → Safe preview → Select for current campaign**. In **Campaigns → New campaign**, **Email template** must show that subject and **Uploaded roster** must show your roster's name and count. Working copy and Clone as Draft are not selection controls. |
| Campaign set up | Select `example.com` under **Sending domain** and check **Sender mailbox**. Use a unique title and a start/end window inside the saved authorization. **After-click content** supplies the approved lesson; **Advanced delivery settings → Training domain** must read `127.0.0.1` in this loopback trial. Create the campaign; find its highlighted row under **All campaigns**. |
| Exact roster confirmed | **Confirm recipients** on that row shows `example.com`, **2 recipients included; 0 excluded**, the chosen email and both masked recipients. Press **Confirm recipients** once. The row must say **Recipients confirmed. Next: Send test email …**. If counts differ, cancel and investigate before sending. |
| Test queued and accepted | On this campaign's row select **Send test email** and the same button in the dialog. Expect **Test email queued — waiting for delivery confirmation** or, if the worker finishes quickly, **Test email passed**. At **Mailpit**, find the message addressed to your synthetic canary. After server confirmation the row offers **Send campaign**. A button's blue color alone is not proof of a send. |
| Roster send completed | Select **Send campaign** and confirm **Send campaign** in its dialog. The row says **Campaign send started**. In **Mailpit**, find one message addressed to your participant; the canary should not receive a second campaign message. Delivery starts at the campaign's configured start time. |
| Training works | Open the participant's captured Mailpit message and follow its training link. Read the lesson, answer the knowledge check and select **Submit answer**. The page must show **Training complete**. |
| Results and downloads work | Return to **Campaigns → All campaigns → this row → Report**. Under **Transport states**, **Provider-accepted handoffs** should be 2. Inspect **Failure reasons** for no failures and **Training** for one completed learner. Select **Download report CSV** and **Download evidence bundle** and verify both files open. Mailpit SMTP acceptance does not produce an external delivered receipt. |
| Audit and stop work | **More → Audit → Recent events** lists `campaign.submit`, `campaign.canary.queue`, `campaign.canary.succeeded` and `campaign.publish.full`; hover the abbreviated Object reference to see the full ID from your evidence bundle. **Verify chain** should show **Chain OK**. Return to your campaign row and select **Recall**. Its state becomes **recalled**; Audit records `campaign.recall`. Do not use the sidebar's global stop for this trial. |

If a request-limit message appears, follow its wait instruction and retry the
same action once the cooldown has elapsed. Do not repeatedly click Send or
start another campaign. If the test is failed/expired, record the displayed
reason and stop this trial rather than asserting success.

The reported-mail collector reads employee-reported phishing; it does not verify
target mailboxes and is outside this CSV trial. Address/domain validation is not
mailbox-existence or inbox-delivery verification. The current server still
requires campaign-bound canary evidence; making the canary optional is a
separate launch-policy decision, not a claim of successful testing.

D6 requires a fresh unaided attempt. Manual keyboard and screen-reader checks
remain separate human evidence; mark unavailable checks pending.


## Previous October 7/8 preparation — superseded controls

**D6 remains open.** The operator reported overlapping template badges,
clipped review states and campaign columns, missing or undiscoverable example
content, and unnecessary pattern/lesson choices. Record this as a failed
usability attempt; do not treat implementation checks as human acceptance.

The console usability repair is deployed on `.105` at merge commit `a87aabf`.
Read-only verification on October 8 confirmed healthy operator/tracking APIs,
live PID entries for all ten workers, and served JavaScript/CSS matching that
commit. Exact-commit CI passed. These checks prepare the repeat attempt; they
do not close D6. See the [resume verification record](QA-REMEDIATION-PLAN-2026-10-07.md#resume-verification--2026-10-08).
Its workflow is documented in [OPERATOR-GUIDE.md](OPERATOR-GUIDE.md#run-your-first-campaign).
Do not use the September environment instructions below as a current runbook.

The training-host follow-up is deployed at `680429c` on
`fix/human-readiness-training-20261008` ([PR #132](https://github.com/ELDSRQ/kingphisher-phoenix/pull/132));
that branch has not been merged into `main`. Its required CI jobs passed.
An automated synthetic backend rehearsal completed canary, separate publication,
recipient training, reporting, exports and recall. That rehearsal remains
distinct from the unassisted human run described here.

The post-deploy browser sweep passed 17 checks with no skips and no blocking
axe findings. Campaign forms were visually checked at desktop and tablet
widths. The build is ready for this controlled human trial. On October 8, the
user explicitly deferred console-password rotation until signing off on the
build as fully completed and human ready. Rotation is not a prerequisite or
blocker to that trial; use the existing protected credential retrieval. D6 and
manual keyboard/screen-reader acceptance remain open. Refresh the console
before starting. Final follow-up commits change test pacing and evidence
records only, so the deployed runtime assets remain those of `680429c`.

Current local access, with the console tunnel running:

- Console: **http://127.0.0.1:8600/console/**. Sign in with the existing console
  password; this on-prem instance uses a single operator identity.
- Test inbox: **http://127.0.0.1:8025/**. Mailpit is the configured capture
  destination. This verifies captured test mail, not real-domain inbox delivery.
- Recipient links use the tracking tunnel on **http://127.0.0.1:8001/**;
  open the exact link in the captured email.

For the repeat attempt, ask the driver to complete this task using the console's
own labels and guidance:

1. **Domains & RoE**: select or verify an authorized sending domain and record
   its Rules of Engagement, including recipient-domain scope and valid dates.
2. **Recipients → Upload a roster**: name the roster, upload a CSV with an
   `email` column, inspect the preview, then apply it. Leave deactivation off.
   Include one authorized synthetic canary account in that exact roster. In
   its recipient row, use **Designate test account**, provide an audit reason
   and complete the displayed confirmation before launch review. Importing a
   CSV does not grant test-send eligibility automatically.
3. **Template review → Choose an email**: preview an approved library email
   and select **Use this email**. If adapting it, use **Edit wording & graphics**,
   then preview and approve the new copy in **Draft review**.
4. **Campaigns → New campaign**: select the domain, saved roster, email and
   future send window. The internal category and approved after-click page
   have defaults. No lesson or question authoring is required.
5. **Configure audience**: verify the exact saved roster and any exclusions,
   save/preview it and freeze it. Review the launch, send the designated test
   cohort first, and verify captured messages before publishing the reviewed
   roster when the server permits it.
6. Open the captured email's link, inspect results and the audit trail, and
   demonstrate how to stop the campaign.

Use newly valid campaign dates. The old example campaign `639ff281` expired
on October 6 and is not a current runnable example. Do not send to a real
roster as part of a synthetic Mailpit acceptance attempt.

Operator preparation verified October 8: use `example.com` for the synthetic
scenario. Its current signed RoE covers September 20–December 20, 2026; the
mixed-domain September 29–October 2 RoE is expired. Recheck coverage at run time.
Training setup now points to the existing tracking tunnel and mirrors the
worker allowlist. The campaign's recipient-page host comes from that setup.

For a new acceptance roster, use only clearly synthetic addresses, for example:

```csv
email,name,department
d6-canary@example.com,D6 canary,D6 synthetic exercise
d6-participant@example.com,D6 participant,D6 synthetic exercise
```

Designate only the canary row. Name each repeat upload distinctly. Keep the
scenario's roster and campaign separate from automated rehearsal records;
retain captured mail, campaign state and audit evidence after the attempt.

Record completion, wrong turns, hesitation and any assistance required. Human
acceptance requires a fresh unassisted attempt after the repair; it does not
follow automatically from a passing test suite.

## Historical September evidence — superseded setup instructions

The material below records earlier findings. Its ports, AI-host instructions,
approval assumptions and environment status are historical, not current setup
instructions. In particular, a second identity is not required by the current
on-prem single-operator policy.

The last on-prem readiness gate. **A non-technical operator drives a full
campaign lifecycle unassisted.** Everything else that has been closed —
D1 full suite, D2 release images, D3 automated accessibility, D5 recovery — is
proxy evidence. This is the real test, and it cannot be automated: the thing
being measured is whether a human can do the job without help.

## Ground rules that make the result meaningful

1. **The driver must not be the person who built it.** If you narrate or
   rescue, the run proves nothing.
2. **Do not fix anything mid-run.** Write it down and carry on. A workaround
   applied live converts a finding into a silent pass.
3. **Record where they hesitate**, not just where they fail. A five-minute
   pause on an unlabelled control is a finding even if they eventually succeed.
4. **Stop and record if they would have given up.** "Got there eventually after
   being told" is a fail for this gate.

## Before you start (operator, not the driver)

The model must be warm before you start. Generation will appear hung if you
skip this.

**Do not rely on a fixed wait — poll the endpoint.** Load time varies by more
than an order of magnitude depending on whether the 18 GB weights file is
already in the OS page cache:

| Case | Observed |
| --- | --- |
| Warm (file in page cache, e.g. after a recent load) | ~30 seconds |
| Cold (first read from disk after boot) | materially longer — minutes |

An earlier version of this document claimed "over twelve minutes". That was
wrong: the figure came from probing a service that was being repeatedly killed
mid-load by GPU contention, so it never finished. Once the contention was
resolved a warm load completed in 30 seconds. The honest answer is that the
cold figure has not been cleanly measured, because doing so means dropping page
cache on a host another product shares.

```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/alice_dr_ed25519 erikd@192.168.1.36 \
  "wsl -d Ubuntu-24.04 -u root -e curl -s http://127.0.0.1:18082/v1/models"
```

Expect `qwen3-30b-a3b-aggregate`. If it says `"Loading model"`, wait and retry
until it answers — do not start the run, and do not assume a duration.

> **GPU CONTENTION — RESOLVED 2026-09-22, but know the signature.** Alice's
> single 24 GB RTX 3090 is shared with another product (Scribe on `.216`), whose
> model is a similar size. Only one can be resident. For a period, something
> outside systemd repeatedly issued `systemctl stop` against `kp-aggregate`
> (`NRestarts=0`, clean `Deactivated successfully`), killing each load after
> 19–42 seconds — just short of the ~30 seconds a warm load needs. The service
> therefore appeared permanently stuck at `"Loading model"`.
>
> Verified resolved: 11 of 12 consecutive probes served over three minutes, with
> 19.5 GB resident. If generation stalls mid-run, check
> `journalctl -u kp-aggregate` for `Stopping` entries before blaming the
> console — a recurrence is an environment fault, not a usability finding.

Open the console tunnel and leave it running:

```bash
ssh -N -L 18000:127.0.0.1:8000 erikd@192.168.1.105
```

Fetch the console password and hand it to the driver:

```bash
ssh erikd@192.168.1.105 \
  "wsl -e bash -c \"grep '^KP_CONSOLE_PASSWORD=' /home/builder/phishing-awareness-platform/.env | cut -d= -f2\""
```

Console: **http://localhost:18000/console/**

## Pre-run state, verified on `.105` 2026-09-25

Checked before scheduling a driver, because three of these would have wasted
the run. Each was observed, not assumed.

| Thing | State | Consequence for the run |
| --- | --- | --- |
| Console | **up** — `127.0.0.1:8000/console/` returns `Kingphisher-Phoenix Operator Console` | steps 1-4 are runnable |
| API / workers | **up** ~16 h — `kp-operator-api`, `kp-tracking-api`, and the ingestion, generation, delivery, retention and mailbox workers | generation worker is listening |
| Supporting services | **up** 3 d — postgres, redis, mailpit, mock-idp, mock-graph, mock-ai, otel | — |
| Real AI gateway | **down** — nothing on `:18081`; the `ai` compose profile is not started | see below |
| `KP_WORKER_AI_BASE_URL` | **empty** | falls back to `mock_ai_url`; generation is served by `mock-ai`, which answers `/propose` in ~3 ms |
| Generation ever run? | **no** — `transactional_outbox` holds `mailbox` and `retention` topics only, zero `generate` rows | step 5 has never executed here |
| Identities | **one** (console password; OIDC 404s) | steps 5-7 blocked, see the correction above |

### Step 5 was run on 2026-09-25 — RESULT

Driven against `.105` through the product's own API as the single console
identity. **The step now completes.**

| Stage | Result |
| --- | --- |
| Clone an approved pattern into a draft I own | `approval_state: draft` |
| **Approve that pattern myself** | `HTTP 200`, `generation_request_recorded: true` |
| `generate` enqueued | first such row ever written on this instance |
| Draft template produced | **5 s** |
| **Approve the draft I requested myself** | `HTTP 200`, `approval_state: approved` |
| Audit trail | `pattern.approve … self_approved=true`, `template.approve … self_reviewed=true` |

Two findings came out of the run, both real.

**1. The shipped local stack could never generate a template.** `.env.example`
pinned `KP_WORKER_AI_MODEL_ID` to the llama.cpp identity while
`KP_WORKER_AI_BASE_URL` was empty — which falls back to the bundled `mock-ai`,
self-reporting `mock-ai/0.2.0`. Every generation job failed the pin:

```
AIResponseError: AI response model does not match the pinned generation model
kp_worker_ai_model_mismatch_total: 2.0
```

It failed the *right* way — closed, audited, retried, then dead-lettered — but
the shipped configuration could not produce a template at all. It had gone
unnoticed because the separation-of-duties bar stopped anyone reaching
generation, so the queue stayed empty and the mismatch never got a chance to
show itself. Fixed, with a regression test that compares the shipped pin against
the bundled mock's advertised id.

**2. The timing is still meaningless.** The 5 s above is `mock-ai` answering in
about 3 ms plus queue latency. It proves the *pipeline* end to end; it says
nothing about whether a human finds real generation acceptably fast. A driver
should not be asked "how long did it take?" until a real model is behind the
gateway.

**So step 5 passes as a pipeline test and remains open as a human-experience
test.** Note `.105` now has `KP_WORKER_AI_MODEL_ID=mock-ai/0.2.0`; that must go
back to the served model's exact identity when a real gateway is attached.

### What this means for step 5

Step 5 asks "did AI generation complete? how long?". As the instance stands
that question cannot be answered honestly, for two independent reasons, and
fixing one does not fix the other.

1. **It cannot be reached.** ~~Generation is queued by pattern approval
   (`routes/patterns.py`), and approval refuses `pattern.created_by ==
   principal_id`.~~ **FIXED 2026-09-25.** Both content bars now honour the
   `single-operator` posture, so the sole operator can approve the pattern they
   curated and the draft they requested; each decision is audited with
   `self_approved` / `self_reviewed`. The stack must actually be set to
   `single-operator` — `.105` was on `single-admin`, which relaxes neither bar
   and additionally makes an empty allowlist allow-all.
2. **It would not mean anything if it were reached.** With
   `KP_WORKER_AI_BASE_URL` empty the draft is produced by `mock-ai` in about
   3 ms. Timing a mock tells you nothing about whether a human finds real
   generation acceptably fast, which is what the step is for.

Note that `/extract` 404s against `mock-ai`, which looks alarming and is not:
`jobs.py` degrades that to "no record" and generates from the pattern alone, by
design.

**Recommendation: do not run step 5 until an identity provider and a generation
backend are chosen.** Both are configuration, not development. Running before
then produces a confident-looking pass that measures a mock and a bypassed
gate.

## The run

Give the driver the URL and password and nothing else. No walkthrough.

| # | Step | Record |
| --- | --- | --- |
| 1 | Sign in | time; anything confusing about first-run credentials |
| 2 | Find where a campaign is created | time to locate; wrong turns |
| 3 | Add recipients | did import/entry make sense without explanation? |
| 4 | Establish a sending domain / RoE as prompted | were the obligations legible? |
| 5 | Create or select a template | did AI generation complete? how long? |
| 6 | Submit the campaign for review | did they understand what review means? |
| 7 | Approve as the second identity | **expected friction — see below** |
| 8 | Schedule / launch the canary cohort | did they understand canary vs full? |
| 9 | Observe results and the audit trail | could they tell what happened and to whom? |
| 10 | Stop or complete the campaign | could they stop it if they wanted to? |

### Step 7 is the one to watch

Self-approval is barred unconditionally. On-prem runs in dev OIDC mode with a
single console password, so the driver may be unable to produce a second
identity at all. **If they cannot complete approval, that is the finding** —
record it and move on. It is a design consequence, not driver error, and it is
exactly the kind of thing this gate exists to surface.

(On Azure the second identity is provisioned and verified:
`licensing@erikdierksgmail.onmicrosoft.com`, a distinct `oid`, `administrator`
role.)

**Correction, 2026-09-25.** This section used to say on-prem had no second
login configured, which understated the problem in one direction and overstated
it in the other. On-prem ships *five* distinct role-bearing identities —
`infrastructure/mock-services/mock_idp.py` defines `author`, `security`,
`privacy`, `operator` and `administrator`, each with its own stable UUID. The
capability is not missing. What is missing is the wiring: the running `.105`
instance authenticates with `KP_CONSOLE_PASSWORD` only, no `KP_OIDC_*` is set,
and `/api/v1/console/oidc/login` returns 404. So the run has exactly one
identity available, and every second-identity gate is unreachable — not because
the product lacks the concept, but because this deployment is not configured
for it. See "Pre-run state" below: this blocks step 5 as well as step 7.

## Recording the result

For each step: completed unaided / completed with hesitation / needed help /
blocked. Note the wording of anything misread. Keep the driver's own phrasing —
"I don't know what this wants" is more useful than a tidied paraphrase.

**The gate passes only if every step is completed unaided.** Anything less is a
list of things to fix, which is a good outcome — it is what the run is for.

## After the run

Warm-model and stack state can be re-verified with
`scripts/operator/verify-second-approver.sh` (Azure identity) and
`./scripts/verify_install.sh` on `.105` (on-prem services).
