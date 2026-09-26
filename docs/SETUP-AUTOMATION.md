# Setup: what can be automated, what cannot, and why

Written 2026-09-25 while automating domain verification. The purpose is to stop
re-litigating "could the console just do this for me?" for each step in turn.

Three categories are used throughout:

- **Automated** — the platform does it; the operator sees a result, not a task.
- **Machine-assisted** — a human decision or an external system is genuinely
  required, but the platform removes the guesswork around it.
- **Irreducibly manual** — automating it would mean holding credentials or
  making an assertion only a human can make.

## The setup path, step by step

| # | Step | Category | State |
| --- | --- | --- | --- |
| 1 | First-run console password | Automated | Generated; operator reads it once |
| 2 | Get the DNS records for a sending domain | Automated | `/sending-domains/challenge` emits the exact records |
| 3 | **Publish those records at the registrar** | **Irreducibly manual** | See below |
| 4 | **Confirm they are live, and record the proof** | **Automated (2026-09-25)** | Console polls and records it itself |
| 5 | Record domain-owner authorization (RoE) | Machine-assisted | Checkbox + who authorized it; everything else defaulted |
| 6 | Import recipients | Machine-assisted | CSV with aliased headers; validation explains rejects |
| 7 | Choose or generate a template | Automated | Approving a pattern queues generation |
| 8 | Create and submit the campaign | Machine-assisted | Freezes what was approved |
| 9 | Approve | Depends on posture | `single-operator`: submitting approves it |
| 10 | Canary, then publish | Machine-assisted | Canary is a gate, deliberately not skippable |

## Step 3 is the one that cannot be automated

Publishing DNS requires write access to the operator's zone. Automating it means
one of:

- **holding registrar API credentials** — the platform would gain the ability to
  rewrite a customer's DNS, which is a far larger blast radius than sending
  simulated mail, and a credential store we do not want to be responsible for;
- **running as a DNS provider** — out of scope;
- **asking for zone delegation** — a much bigger ask than the problem justifies.

So step 3 stays manual. What was wrong was leaving steps 3 and 4 *equally*
manual: the operator pasted records, clicked "Verify now", and got one pass/fail
toast with no way to tell whether they had made a mistake or DNS had simply not
caught up. That is the part that felt like guesswork, and it is now automated.

## What step 4 does now

`POST /sending-domains/diagnose` resolves every record the wizard asked for and
reports each one separately: what was expected, what is actually published, and
which of five states it is in. The console polls it and records the verified
domain the moment ownership is provable — no button.

The distinction that carries the weight is **`absent` vs `mismatch`**:

- `absent` — nothing published at that name. Almost always propagation still in
  flight. The answer is "wait", and the console says so instead of reporting a
  failure.
- `mismatch` — something IS published and it is wrong, so waiting will never
  help. The console shows the published value next to the expected one, which is
  usually enough to see it is a stale challenge from an earlier attempt.

A pass/fail check renders those two identically while they mean opposite things.

SPF and DMARC are reported but never block verification — a domain that already
sends mail legitimately carries its own SPF, and the console says so rather than
calling it an error. DKIM reports `not_checkable`, because the relay chooses the
selector and claiming otherwise would be a lie.

After two consecutive non-propagation failures the console raises the registrar
trap: several providers silently drop custom records when an email-forwarding
feature is enabled, which presents as records that were definitely saved and are
definitely gone.

## Step 5: authorization is already close to minimal

The RoE is a signed artifact because scheduling and delivery re-verify it
(`roe_covers_schedule`, `recipient_domain_roe_covered`) — dropping it would mean
deleting those checks, not simplifying a form. What was simplified is the
*asking*: a checkbox confirming the domain owner authorized the exercise, plus
who they are. Target domains default to the ones just verified, terms to a
standard text, window to twelve months.

That is the right shape. The assertion "the domain owner authorized this" is
exactly the kind of thing only a human can make, so it stays a human action —
but it should cost one tick, not a five-field form.

## What is left

- **Recipient import** ~~could preflight against the RoE target domains~~
  **DONE (2026-09-26, PR #74)**: the import preview now reports how many
  recipients sit in domains no active RoE covers, at import time.
- **SPF**: ~~the domain-verify check and the delivery check could share one
  verdict.~~ **On inspection, they should NOT be merged.** They intentionally
  check different things: domain-verify (`diagnose`) checks whether the
  *verified domain* publishes an SPF record; delivery (`jobs.py`) checks the
  *effective sender address's* domain, which under ACS deliberately differs from
  the campaign's configured domain (an earlier bug came from checking the wrong
  one). Two correct checks at two times, not one duplicated verdict. Left as is.
