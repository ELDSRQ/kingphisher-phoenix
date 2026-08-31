# AI-010 model selection — Qwen2.5-7B-Instruct

**Decision (2026-08-31): the operator selected `Qwen2.5-7B-Instruct` (Q4_K_M)**
as the internal generation model for AI-010, after reviewing the six-candidate
bake-off. This document is the digest-pinned selection evidence AI-005 requires.

## Pinned identity

The product pins the selected model through `KP_WORKER_AI_MODEL_ID`
(`apps/workers/src/kp_workers/config.py:199`, required for the `generation`
worker at `config.py:349`). The canonical identity for this selection is:

```
llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M
```

## Digest-pinned artifacts

| Artifact | SHA-256 |
|---|---|
| `qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf` | `85cb3cc4a0f9533795fd6881c4d5f289c14b24668b4fb2a8fc0ee73832cdf265` |
| `qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf` | `539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a` |
| `LICENSE` (Apache-2.0) | `832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e` |

- **Source repo:** `unsloth/Qwen2.5-7B-Instruct-GGUF` (a trusted conversion; not
  an `uncensored`/`abliterated` variant, which are rejected because they remove
  the alignment the defensive framing depends on).
- **Runtime:** `llama.cpp` 0.3.0 build 10621 commit `c1d0e7a00`, quant `Q4_K_M`.
- **Decoding:** `response_format: {"type":"json_schema", ...}` bound to
  `GenerationResponse.model_json_schema()` — schema-constrained.
- **Evaluation set:** version `3.0`, digest
  `216fdddad805879b4ee166736354d83007cf7c41f8e30451ced8977bbaac7b26`.
- **Scorer:** version `2.1.0`.
- **Report:** `qwen2.5-7b-instruct-bakeoff.json` (this directory).

## Why Qwen2.5-7B

Measured on set 3.0 / scorer 2.1.0, it is the only candidate that passes safe
refusal cleanly **and** is fast enough for AI-005's CPU-first requirement:
schema 4/4, safe refusal 1/1, injection 1/1, fidelity 3/4, median latency
13.6 s. Its single miss is minor and genuine — it genericised the
"shared-document" lure to "the attachment... a training document".

The alternatives each had a disqualifying issue for this product: Mistral-7B
had better raw fidelity (4/4) but wrote a genuine-looking security alert rather
than something recognisable as a simulation (safe refusal 0/1); Phi-4-mini
omitted the mandatory training placeholder; the 9B and every 20B-class model
were disqualified on CPU latency (9B ~420 s/case; dense 27B 0.17 tok/s; MoE
gpt-oss-20b 0.44 tok/s). Full comparison table is in `RESUME-HERE.md`.

## Open items this selection does NOT close

1. **The pinned llama.cpp worker role/deployment does not exist yet.** The
   product's generation path currently POSTs to an operator-configured
   out-of-tree `/propose` gateway (`apps/workers/src/kp_workers/jobs.py`), so
   selecting the model does not by itself make internal generation live. Standing
   up the pinned `llama.cpp` role that serves this model is the remaining AI-010
   implementation work and needs the external deployment.
2. **The deployment must inject the pinned `model_id`, not trust the model's
   self-report.** During the bake-off the raw model invented `model_id` values
   (e.g. `phishing_simulation_2026`). The product compares the returned
   `model_id` against the pin, so the serving layer must set `model_id` to
   `llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M` rather than relying on the model to
   emit it. See `docs/ai010-worker-parity.md` finding #3.
3. **One scorer limitation remains** (the 40-char attribution window; see
   `RESUME-HERE.md`). It does not affect this selection's standing but should be
   resolved before the numbers are treated as final for any other purpose.
4. **Independent review** of this selection remains an AI-005 requirement.
