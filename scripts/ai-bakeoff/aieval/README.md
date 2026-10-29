# W3-04 AI quality / privacy / cost evaluation harness

Additive, offline, deterministic. It operationalises **KP-AUD-010/012 +
Report-04**: AI proposals are measured against the deterministic baseline so AI
is used only where it adds measurable teaching/realism value, and unnecessary
egress is restricted.

Nothing here edits or calls the AI gateway. It reads the shared contracts
(`kp_contracts.cue_ontology`, `kp_contracts.generation`, `kp_contracts.discovery`)
and the operator provider registry (`kp_operator_api.ai_providers`) as data, and
reuses the AI-010 scorer in `../bakeoff/scoring.py` unchanged.

## Pieces

- **`evaluation_set.yaml` + `eval_set.py`** — a versioned, digested, fictional,
  inert evaluation set. Each case carries a synthetic `lure_source`, the
  ground-truth `expected_cue_types` (from the W3-01 cue ontology), expected
  lure-content `expected_fragments`, a deterministic `realism_rubric`, and
  per-case `cost_latency` budgets.
- **`cue_baseline.py`** — the deterministic cue manifest is the ground truth;
  this extracts cues from an AI output with the *same* extractor and scores how
  many baseline cues survive. The AI is measured against the baseline, never the
  other way round.
- **`realism.py`** — bounded, offline structural realism checks (subject,
  training placeholder, call-to-action, no self-identifying disclaimer, cue
  coverage). A human still approves every draft.
- **`provider_telemetry.py`** — per-provider usage + circuit telemetry carrying
  only counts, latency, and token totals. The recording API has no parameter
  through which a prompt or completion could be passed, so raw content is never
  logged. Exports through the bounded `kp_telemetry` metric registry.
- **`egress_policy.py`** — discovery defaults to local threat metadata; a hosted
  (offsite) provider or hosted web-search discovery requires an explicit
  acknowledgement. The one PII guard is the `@`-backstop
  `assert_pii_free_query` (W1-05); this module adds no second "no PII" claim.
- **`offline_bakeoff.py`** — the reproducible, **mock-recorded** bake-off. It
  reads approved provider recordings from `recordings/` (no live call anywhere),
  scores each provider on safety, cue-validity, realism, latency, and tokens,
  and emits a per-provider report with token use **by provider**, a
  reviewer-preference placeholder, and an enable/disable recommendation.

## Run

```bash
uv run python scripts/ai-bakeoff/aieval/offline_bakeoff.py \
    --report /tmp/w3-04-bakeoff.json
```

A provider is recommended for **disable** when it is unsafe, when its egress is
not acknowledged, or when a hosted option adds no measurable gain over the
deterministic baseline (so egress/cost is not justified). `reviewer_preference`
is left `null` for a human to fill.

## Recordings

`recordings/*.json` are inert, synthetic, approved outputs — no PII, no network.
A recording is untrusted evaluation data: every field is bounded and nothing in
it is executed or trusted as an instruction.

## Tests

```bash
uv run --frozen pytest tests/ai_eval -q
```

Fully offline; no model, provider, or network is required.
