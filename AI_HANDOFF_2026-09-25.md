# AI Handoff — 2026-09-25

Canonical current-state handoff. Supersedes `AI_HANDOFF_2026-09-19.md`. The
project's auto-memory (loaded each session) holds fine-grained detail; this doc
is the self-contained map. Copy-ready resume prompt: `NEXT_AI_PROMPT.md`.

`main` at the merge of the handoff PR; CI green, **zero open PRs, no local
branches but `main`, working tree clean**. This session landed **PRs #61–#72**.

---

## The headline: this is now a real one-operator product

A single console identity can run the entire campaign lifecycle end to end, with
no second person and no identity provider. This was the session's main work.

- **Content approval honours `single-operator`** (PR #67). Approving a pattern and
  approving the AI draft you requested are no longer barred for the sole
  operator; each is audited with `self_approved` / `self_reviewed`. `ENFORCE` is
  unchanged; `SINGLE_ADMIN` deliberately does **not** gain this.
- **The recipient allowlist no longer fails closed under `single-operator`**
  (PR #68). An unset `KP_ALLOWED_RECIPIENT_DOMAINS` now admits, because the
  binding control is the signed RoE (`recipient_domain_roe_covered`), which
  delivery enforces independently and "cannot be switched off by config". Not
  allow-all. `ENFORCE` still fails closed; `SINGLE_ADMIN` still needs dev markers.
- **A shipped dev-stack bug was found and fixed** (PR #70): `.env.example` pinned
  `KP_WORKER_AI_MODEL_ID` to the llama.cpp identity while the default backend is
  `mock-ai` (self-reports `mock-ai/0.2.0`), so every generation job dead-lettered
  and the default local stack could never produce a template. Pin now matches the
  mock; regression test guards it. See memory
  `generation-model-pin-must-match-backend`.
- **`.105` runs `OPERATOR_APPROVAL_POLICY=single-operator`** as of this session.

See memory `pattern-approval-needs-second-identity` (corrected this session) for
the four identity bars and exactly what gates each.

## D6 step 5 — RUN and PASSED (as a pipeline test)

Driven through the product API on `.105`: clone approved pattern → **self-approve
pattern** (HTTP 200) → generation fired (first `generate` row ever on that
instance) → draft produced in ~5 s → **self-approve draft** (HTTP 200). Audit
shows `self_approved=true` and `self_reviewed=true`.

Steps 6–10 also proven end to end on `.105` earlier: canary (test cohort only) →
full publish (5/5 ACCEPTED to Mailpit) → `/report` results → **recall** (5 tokens
revoked). Delivery goes to Mailpit via local SMTP.

**Still open on step 5:** the 5 s is `mock-ai` (~3 ms) plus queue latency — it
proves the pipeline, NOT human-acceptable generation speed. That needs a real
model behind the gateway. `.105` has no GPU/weights; Alice has ~4.7 GiB free vs a
~4.5 GiB model — neither is a good host yet. Decision deferred.

## Console simplification (PR #72) — BUILT, DEPLOYED, UNSEEN IN A BROWSER

Operator feedback drove this; all verified at API/contract level, none seen render.
- **Sidebar grouped**: 7 campaign-path items, the other 13 behind a "More"
  disclosure. Nothing removed.
- **New-campaign form prefilled**: title (pattern+month), start (next whole hour),
  end (+14d), max-recipients (imported count), approved pattern/template/lesson.
  Sender + training domain fill ONLY when exactly one domain is verified — `.105`
  now has two, so those two fields are intentionally blank (guarding against a
  wrong From on real mail). This is correct behaviour, not a bug.
- **Programs** rewritten: leads with what it's for, says it's optional, explains
  its empty state; its three review guarantees are unchanged and still pinned.
- **`docs/START-HERE.md`**: ordered first/second/third guide — four human inputs
  total (domain, one authorization tick, recipient CSV, approve the AI draft).

## Domain verification is now self-checking (PR #71)

`POST /sending-domains/diagnose` (read-only) reports every required record's live
state, distinguishing `absent` (still propagating — wait) from `mismatch`
(published-but-wrong — fix). The console polls it and records verification itself,
no button. `/verify` unchanged and still the only thing that records.
`docs/SETUP-AUTOMATION.md` records what is automated / machine-assisted /
irreducibly manual. `mock-idp` issuer is now env-configurable (PR #66).

## Sending domain: mail.floridamanevolved.us is LIVE

- **`mail.floridamanevolved.us`** is verified in Azure ACS (Domain/SPF/DKIM/DKIM2)
  AND in the KP console (`verified_domains`, by the console identity). ACS
  deliverability proven this session via a direct `az communication email send`
  (`status: Succeeded`) from `DoNotReply@mail.floridamanevolved.us`.
- The KP `verified_domains` record is in the **`.105` DB**. The Azure staging DB
  is separate and does NOT have it — a full campaign-via-ACS would need the Azure
  DB populated from scratch. Sending via ACS is the **Azure** path; `.105` sends
  via local SMTP → Mailpit, so ACS is irrelevant on-prem.
- Namecheap DNS for `floridamanevolved.us`: apex SPF cleaned, `mail.*` fully
  verified. Keep Mail Settings = "No Email Service" so records are not purged
  (memory `namecheap-email-forwarding-purges-records`).

## Alice on-prem model host — boot persistence FIXED

The aggregation model (`.36`, RTX 3090, WSL2) kill cycle is resolved (PRs #61,
#63, #65). Boot persistence REQUIRES an **S4U scheduled task** — SYSTEM is
impossible (`WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED`), a logon task misses unattended
reboots — plus a resident `sleep infinity` session holder. Health monitor now a
systemd unit. Model held stable for hours. **Still unproven: an actual reboot.**
Full detail in memory `alice-rtx-aggregation-model-host`.

## Azure staging — FLOORED (idled to the safe maximum)

Powered down after the ACS test. Current floor:
- Postgres **Stopped**, runner VM **deallocated**, operator/tracking/ai-gateway
  apps **0 replicas**, orphaned revisions **deactivated**.
- The `ca-kp-staging-worker` app holds **1 stuck replica** (min-0, no scale rule)
  that cannot be cleared without a rebuild — left in place.
- **Left UP (rebuild-costly, do NOT destroy):** Redis Enterprise, ACR Premium,
  NAT gateway + IP, 5 private endpoints, ACS, Key Vault, audit/tfstate storage.
- Residual ≈ **$270/mo structural + ~$30–60/mo stuck worker**. The only lever
  lower is `azure-idle.sh stop` (terraform-destroys Redis+ACR), which forces a
  multi-hour re-bootstrap — currently excluded by operator instruction.
- To resume Azure: `scripts/operator/azure-nightly-shutdown.sh` is the idle
  script; bring PG/VM/apps back up before Azure work.

## Standing rules (unchanged, still binding)

- **Production and RSA use remain NO-GO** until the full gate set is proven
  (AGENTS.md). Nothing here changes that.
- `.105` is a SHARED host (AccessTracker, Procurement — ~47 containers). Never
  touch them; keep compose project-scoped. Its `/tmp` is shared — never use
  generic scratch filenames there (bit us twice; memory
  `docker-images-only-on-105`).
- Never modify other projects. Docker only on `.105`. Never merge with `--admin`.
- Surface every problem with an attached fix or labelled options + recommendation
  — never bury it (memory `always-surface-problems-with-actions`).

## The single biggest open item

**A human browser pass over `.105`.** Everything through recall is proven at API
level, but the console simplification, prefill, DNS-diagnose panel and Programs
rewrite have never been seen render. Tunnel + console:

```
ssh -N -L 18000:127.0.0.1:8000 erikd@192.168.1.105
# http://localhost:18000/console/  — password: KP_CONSOLE_PASSWORD in .105 .env
```

Look at, in order: the sidebar "More" grouping; Campaigns → New (prefill);
Domains & RoE → Onboard (the polling DNS panel); Programs (empty-state copy).

## Other open threads (lower priority)

- Real generation model behind the gateway (hardware decision — see step 5 above).
- Alice reboot proof.
- D3 manual keyboard/screen-reader half of accessibility (operator judgement).
- Azure single-operator parity: staging is still `ENFORCE` and powered down.
