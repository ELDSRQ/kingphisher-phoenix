# D6 — Human acceptance run (on-prem)

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
