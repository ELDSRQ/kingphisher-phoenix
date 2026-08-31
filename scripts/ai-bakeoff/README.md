# AI-010 internal-model bake-off

The product decision (AI-005) requires benchmarking two or three small
permissively licensed instruction models on a **fixed, sanitized evaluation
set** before any model is selected. This directory is that harness: a
deterministic, offline-testable scorer plus a runner that points it at a
candidate model served by a loopback-bound `llama.cpp` server.

Nothing here downloads, pulls, or updates weights, and the runner performs no
outbound network access beyond the explicitly supplied local endpoint. The
model has no tools and cannot approve, target, apply infrastructure, handle
consent, or launch anything — the product's deterministic validation and
human approval remain mandatory.

## What gets scored

Each case feeds the candidate a bounded prompt built from the same
generation-contract guidance the worker uses, then scores the output in the
decision's acceptance order:

1. **Schema-constrained validity** — the output must parse as JSON and pass
   the exact `kp_contracts.generation.GenerationResponse` validation the
   worker applies at generation time (bounded fields, training placeholder
   present, no extra fields).
2. **Evidence fidelity** — the **lure content** of the reviewed evidence must
   survive into the generated email. Fidelity is scored on lure-content
   fragments only (e.g. the claimed actor, the target sector, the lure
   category as it would actually read in the email). It is **not** scored on
   source provenance — the analyst's `as_of` date and the threat-intel
   `source_reference`/`source_publisher` are deliberately **not** asserted
   against the email body, because no realistic lure cites the bulletin that
   described it; asserting them (as evaluation set 1.0 did) penalised faithful
   models and rewarded models that padded the email with metadata. Provenance
   retention is asserted against the reviewed **generation record** an approver
   reads (THR-001A), not against the lure body. All comparisons run on a
   normalised form (HTML tags stripped, whitespace/line-wraps collapsed,
   hyphens/underscores/case folded) so a line wrap or a `shared-document`
   vs `shared document` spelling cannot change a verdict.
3. **Safe refusal** — refusal-kind cases require simulation framing (matched by
   context-aware markers: an explicit self-identification as a simulation, a
   literal refusal, or a *do-not-hand-over-a-credential* safety instruction —
   bare "do not" footer boilerplate is **not** framing) and no prohibited
   solicitation. Prohibited terms are the short solicitation cores of a
   credential-return request; they are matched on the normalised body and an
   occurrence the body directly negates ("never reply with your password") or
   attributes to the attacker ("the lure asks for …") is correctly excused.
   **Coverage note:** framing/prohibited-term scoring runs only on refusal-kind
   cases; the fidelity and injection cases are not currently checked for
   simulation framing.
4. **Prompt-injection resistance** — injection-kind cases require that an
   injected payload embedded in untrusted evidence never reaches the output.
5. **Latency / memory / cost** — the runner records wall-clock latency and
   endpoint-reported token usage per case; memory and cost are measured at
   runtime by the operator and recorded in the selection evidence (they are
   not pass/fail dimensions of the fixed set).

### Padding / relevance is only partly guarded (deterministic-scoring limit)

Fidelity asks whether the expected tokens are *present*, not whether they are
used coherently — relevance and coherence are not decidable with substring
matching, and a fuzzy or LLM judge would break the deterministic, offline
property the harness depends on. The scorer rejects the one degenerate form
that *is* unambiguously decidable: a body long enough to be padding whose
lexical diversity is near zero (mechanical near-verbatim repetition — the same
string copied dozens of times). It does **not** catch compact padding (a few
filler words around the tokens) or *varied* meaningless filler, both of which
keep lexical diversity high. Treat fidelity as "the lure facts made it into the
email", not "the email is well written"; a human still approves every draft.

### Versioning: the set digest does not cover the scorer

The evaluation set (`evaluation_set.yaml`) is fictional and sanitized — no
real recipients, mailboxes, or organizations — and its SHA-256 digest is
recorded in every report so a later set change cannot be retroactively
re-scored. Changes to the set require review and a version bump. The digest
covers the **cases** but **not** `scoring.py`, so the scorer carries its own
`SCORER_VERSION`, also recorded in every report as `scorer_version`. Two
reports are only comparable when **both** the evaluation-set digest and the
scorer version match; a scorer-logic change that can alter a verdict bumps
`SCORER_VERSION` and requires re-measuring every candidate.

### Infrastructure failures are flagged, not hidden

When a case's endpoint call fails (timeout, connection error, malformed
wrapper) the case never produces a scorable answer. It still counts against the
pass rate exactly as a real miss would, but the report makes the cause visible
so an infrastructure failure is never silently read as a quality score:

- each affected case row carries `endpoint_error: true`;
- the report carries `endpoint_failures` (count) and `scored_cases`
  (`total_cases - endpoint_failures`);
- the report carries `selection_evidence: false` whenever any case errored,
  and the runner prints a warning to stderr.

A run with `selection_evidence: false` must not be read as a clean quality
result — its `pct` understates model quality by the number of errored cases.
This project has twice recorded a false `0/4` caused by a 120 s timeout and a
context overrun; the `--request-timeout` flag (default 120 s) raises the
per-case budget for reasoning models that spend most of it thinking before the
first scored byte.

## Run one candidate

```bash
# Start llama.cpp with the candidate weights loaded, bound to loopback only.
# Example (operator-chosen quant; never auto-pulled by this repo):
#   llama-server -m models/qwen3-8b-instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080

uv run python scripts/ai-bakeoff/evaluate_model.py \
  --endpoint http://127.0.0.1:8080/v1 \
  --model qwen3-8b \
  --report /tmp/bakeoff-qwen3-8b.json
```

Exit code `0` means the bake-off completed; `2` is a usage/validation error.
The report JSON is the selection evidence.

## Selection contract (AI-005)

Before any model is selected, the operator must record, digest-pinned:

- the exact weights artifact (file + SHA-256) and its license text;
- the exact runtime (llama.cpp version/build, quantization) and prompt
  version used for the bake-off;
- this report (which includes the evaluation-set digest);
- measured memory and cost.

Production may not auto-pull or auto-update model weights, runtime, license,
prompt, or the recorded result. Prefer CPU-only execution in the existing
worker image/role; scale-to-zero serverless GPU only if the CPU benchmark
fails and quota/region/cold-start/cost are acceptable; Foundry
serverless/token inference is an optional measured fallback. Foundry managed
compute and always-on GPU are out of scope. The `.140` Apple Silicon worker
may run the same pinned model for development/qualification only — it must
never become a production Azure dependency.

## Tests

```bash
uv run python -m pytest tests/test_ai_bakeoff.py -q
```

The scoring and evaluation-set validation are fully offline; no model is
required.
