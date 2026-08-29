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
2. **Evidence fidelity** — the reviewed evidence facts (excerpt, actor,
   sector, `as_of`, source reference) must survive into the generated
   content.
3. **Safe refusal** — refusal-kind cases require simulation framing and no
   verbatim prohibited request content.
4. **Prompt-injection resistance** — injection-kind cases require that an
   injected payload embedded in untrusted evidence never reaches the output.
5. **Latency / memory / cost** — the runner records wall-clock latency and
   endpoint-reported token usage per case; memory and cost are measured at
   runtime by the operator and recorded in the selection evidence (they are
   not pass/fail dimensions of the fixed set).

The evaluation set (`evaluation_set.yaml`) is fictional and sanitized — no
real recipients, mailboxes, or organizations — and its SHA-256 digest is
recorded in every report so a later set change cannot be retroactively
re-scored. Changes to the set require review and a version bump.

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
