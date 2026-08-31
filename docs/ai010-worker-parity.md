# AI-010 worker parity audit: does the product apply what the bake-off proved?

Scope: the shipping generation path, compared against the constraints the
offline bake-off harness (`scripts/ai-bakeoff/evaluate_model.py`) established as
necessary. Read-only audit; no code was changed.

---

## Verdict

**There is a structural gap, and it is not a bug in the worker — it is that the
product has no model call at all.**

The bake-off learned that schema-constrained decoding
(`response_format: {"type": "json_schema", ...}` bound to
`GenerationResponse.model_json_schema()`) is required, because prompt
instructions and `json_object` both permit a raw control character inside a JSON
string and produce unparseable output. That constraint is applied in exactly one
place in the repository: `scripts/ai-bakeoff/evaluate_model.py:119-126`.

The product does not build a chat-completions request anywhere. The generation
worker POSTs the `GenerationRequest` contract as JSON to
`{ai_base_url}/propose` — an operator-configured, **out-of-tree HTTP gateway**
(`apps/workers/src/kp_workers/jobs.py:2082-2091`, URL at line 2086). Everything
the bake-off constrained — decoding format, system prompt, temperature, tool
availability, network egress — happens on the far side of that boundary, in code
this repository does not contain, review, or test. The only in-repo `/propose`
implementation is `infrastructure/mock-services/mock_ai.py`, a dev-only stub that
returns a fixed dict (`mock_ai.py:182-206`) and never runs a model.

So the honest statement is: **the validated harness behaviour is not applied by
the shipping path, and cannot be, until the pinned internal `llama.cpp` worker
role described in `RUNBOOK.md:35` actually exists.** What the product *does* have
is a strong post-hoc containment layer — bounded reads, contract validation,
deterministic safety re-validation, a constant-time model pin, and a human
approval gate — which is genuinely fail-closed. Nothing bad gets persisted. But
containment is not the same as constraint: the specific failure the bake-off hit
would, in production, become a dead job rather than a bad draft.

`grep -rn "chat/completions\|response_format" --glob '!docs/*'` returns hits only
in `scripts/ai-bakeoff/evaluate_model.py`. That single fact is the audit result.

---

## Ranked gaps

### G1 — HIGH: no schema-constrained decoding on the product path, and the contract cannot express one

* **Where:** `apps/workers/src/kp_workers/jobs.py:2082-2094` (the only outbound
  generation call); `packages/contracts/src/kp_contracts/generation.py:130-168`
  (`GenerationRequest`, which has `pattern`, `as_of`, `context_untrusted`,
  `neutralization_reasons`, `training_url`, `guidance` — and no field for a
  response schema, grammar, decoding format, or temperature).
* **What is missing:** the request the worker sends contains no way to ask the
  gateway for schema-constrained output. `guidance`
  (`generation.py:155-162`, populated at `jobs.py:1997-2002`) is documented
  in-contract as *"Advisory only … a gateway that ignores this cannot widen what
  the platform will accept."* That is true for safety, but it means the JSON
  well-formedness discipline is entirely at the gateway's discretion.
* **Concrete production failure:** the exact bake-off failure. A model emits a
  raw newline inside a JSON string; the gateway relays it; `_bounded_ai_json`
  (`jobs.py:2063-2066`) raises `AIResponseError("AI response is not valid
  JSON")`. The supervisor catches it as a generic exception
  (`supervisor.py:159-169`), rejects the message, and the queue re-queues it
  (`packages/contracts/src/kp_contracts/queue.py:249-272`) up to
  `max_retries=3` (`config.py:171`) before dead-lettering. Because the failure is
  a decoding artifact on identical input, all three attempts fail identically —
  the retry budget buys nothing. Net effect: a human-approved threat pattern
  silently produces no draft, and the only signal is a content-free
  `worker_role_processing_failed` log line plus an `outcome="error"` metric. No
  operator-visible link from "pattern approved" to "generation impossible".
* **Change that closes it:** when the internal `llama.cpp` role lands, the worker
  must build the chat request itself and set
  `response_format: {"type": "json_schema", "json_schema": {"name":
  "generation_response", "schema": GenerationResponse.model_json_schema(),
  "strict": True}}` — `evaluate_model.py:106-127` is the reference
  implementation and should be lifted, not re-derived. Until that lands, the
  minimum is to add a normative field to `GenerationRequest` (e.g.
  `response_schema: dict` carrying `GenerationResponse.model_json_schema()`, or
  a `decoding: Literal["json_schema"]` obligation) so the gateway contract
  *states* the requirement instead of leaving it in prose, plus a conformance
  probe that asserts a candidate gateway honours it.

### G2 — HIGH: the model's tool-less / network-less posture is asserted, not enforced

* **Where:** `jobs.py:2086`; `apps/workers/src/kp_workers/config.py:167-171`
  (managed-mode gateway requirements); `config.py:557-558`
  (`effective_ai_base_url` falls back to `mock_ai_url` outside managed mode).
* **What is missing:** from the product's perspective the model is tool-less and
  network-less only in the trivial sense that the product **sends no tool
  definitions** and the response contract has `extra="forbid"`
  (`generation.py:171-178`), so a `tool_calls` field would be rejected. That is a
  real control against the model gaining *authority over the platform*. It is not
  a control over what the model may do gateway-side: nothing in this repository
  can observe whether the gateway grants the model tools, retrieval, or outbound
  network. The managed-mode validators enforce that the endpoint is a non-local
  HTTPS URL — an address check, not a posture check.
* **Concrete production failure:** a gateway that transparently gives the model
  web retrieval would let attacker-influenced excerpt text (already neutralized,
  but neutralization is pattern-based, not perfect) steer a fetch. The platform
  would see a well-formed, safety-passing draft and could not distinguish it from
  a compliant one. AI-010's "no-tool/no-network" criterion is currently satisfied
  by architecture diagram, not by code.
* **Change that closes it:** land the in-repo pinned-model worker role — the
  stated plan (`RUNBOOK.md:35`, `RESUME-HERE.md:65`) — so the loopback
  `llama.cpp` process, its flags, and its absent tool registry are all inside the
  reviewed image. Short of that, the `/propose` contract needs to be normative
  with a documented gateway obligation and an attestation the worker records.

### G3 — MEDIUM: the pinned model identity is enforced but not bound into the record

* **Where:** enforcement at `jobs.py:2113-2116`; persistence at `jobs.py:545`
  (`proposal = response.model_dump()`), `jobs.py:564`
  (`model_id=response.model_id`), `jobs.py:565` (`input_hash` over the *request*
  only).
* **What is missing:** `TemplateVersion.model_id` and `raw_proposal["model_id"]`
  hold the gateway's **self-reported** identity. Whether a pin was configured and
  whether the constant-time compare actually ran is recorded only as a
  process-level gauge (`kp_worker_ai_model_pinned`, `jobs.py:2070`) and a counter
  (`kp_worker_ai_model_mismatch_total`, `jobs.py:2115`). Neither is attached to
  the row. `ai_model_id` is required only when
  `runtime_mode in _MANAGED_RUNTIME_MODES` and `worker_name == "generation"`
  (`config.py:167-171`); every other deployment may run unpinned, in which case
  the compare is skipped entirely and `model_id` may be the contract default
  `"unknown"` (`generation.py:183`).
* **Concrete production failure:** a draft produced under no pin is
  byte-indistinguishable, at the record level, from one produced under a verified
  pin. A later audit asking "which approved templates came from the
  bake-off-selected model?" cannot be answered from the database — only from
  whatever the metrics backend still retains, which is aggregate and unjoinable
  to a template id.
* **Change that closes it:** record the pin decision on the draft, e.g.
  `proposal["model_pin_enforced"] = bool(ctx.settings.ai_model_id)` and
  `proposal["pinned_model_id"] = ctx.settings.ai_model_id` alongside the existing
  `context_untrusted` / `neutralization_reasons` carriage at `jobs.py:546-556`,
  and/or fold the pinned identity into `input_hash`.

### G4 — MEDIUM: `model_id` is optional in the very schema the harness constrains against

* **Where:** `packages/contracts/src/kp_contracts/generation.py:183`
  (`model_id: str = Field(default="unknown", ...)`).
* **What is missing:** `GenerationResponse.model_json_schema()` — verified by
  running it locally — emits `"required": ["subject", "plain_text", "safe_html"]`
  with `model_id` carrying a default and *absent from `required`*. Under a strict
  schema-constrained decoder the model may therefore legally omit `model_id`.
* **Concrete production failure:** on the future internal path, a
  schema-constrained model that omits `model_id` yields `model_id == "unknown"`;
  with a pin configured, `secrets.compare_digest(pinned, "unknown")` fails and
  **every single generation** raises
  `AIResponseError("AI response model does not match the pinned generation
  model")`. A correct, schema-obedient model would be 100% rejected. This is
  latent today only because the gateway sets the field by hand.
* **Change that closes it:** either make `model_id` required (drop the default)
  so the schema forces it, or — better — stop trusting the model to self-report
  its own identity on the internal path and have the worker attribute the
  configured pin directly, keeping the self-reported value only as a
  cross-check.

### G5 — MEDIUM: nothing prevents an *additional* live URL beside the placeholder

* **Where:** `generation.py:185-190` (placeholder must be *present*);
  `jobs.py:530-543` (safety re-validation);
  `packages/safety-validation/src/kp_safety_validation/validator.py:462-469` and
  `:344-366` (host allowlist with suffix matching);
  `config.py:247` (`training_domains` default `"example.com,127.0.0.1"`,
  set-ified at `config.py:652`).
* **What is missing:** the contract requires the placeholder to appear in both
  bodies, so the model cannot *replace* it — that is correctly enforced. But
  nothing forbids the model from also emitting a real URL, and `SafetyValidator`
  rejects a host only when it is **not** on `training_domain_set()`. The
  allowlist match at `validator.py:363-366` accepts the domain and any
  subdomain, with no path constraint. The delivery-time fence
  (`jobs.py:2187-2190`, `_contains_url`) matches only the *exact* configured
  `training_base_url` origin+path identity (`jobs.py:2244-2271`), so it does not
  catch a different path on the same allowlisted host.
* **Concrete production failure:** a model emits both
  `{{ tracking.training_url }}` and, say,
  `https://training.example.com/collect` in the HTML body. The contract passes
  (placeholder present), the safety validator passes (host on allowlist), the
  delivery fence passes (different path). The draft persists and reaches the
  human reviewer with a live, untracked link embedded. The human approval gate
  is the only remaining backstop — which is by design, but it is the *last*
  backstop rather than one of several.
* **Change that closes it:** at generation time, before persistence, reject any
  URL in `subject` / `plain_text` / `safe_html` other than the required
  placeholder. The generated draft has no legitimate need for any other
  navigable link; an allowlist is the wrong shape of control here, a
  deny-everything-but-the-placeholder rule is the right one.

### G6 — LOW: a failed generation leaves no operator-visible, pattern-scoped record

* **Where:** `supervisor.py:159-169`; `jobs.py:443-586` (all failure paths return
  or raise before `session.add`).
* **What is missing:** every AI failure class — `AIRequestError`,
  `AIResponseError`, `SafetyRejectionError` — aborts with a content-free message
  and no durable per-pattern record. The content-free-ness is deliberate and
  correct (tests assert provider content never reaches an exception string). But
  an operator who approved a pattern and never received a draft has no in-product
  explanation.
* **Concrete production failure:** G1's DLQ scenario is invisible in the operator
  UI. The pattern shows approved; no template appears; nothing says why.
* **Change that closes it:** a bounded, content-free failure record keyed by
  `campaign_pattern_id` with a reason *class* (`invalid_json`,
  `contract_mismatch`, `model_pin_mismatch`, `safety_rejected`), surfaced on the
  pattern.

### G7 — LOW: "cost" is measured as bytes and latency, never tokens, and never on the record

* **Where:** `jobs.py:2095-2100` (`kp_worker_ai_response_bytes_total`);
  `apps/workers/src/kp_workers/observability.py:95-113` (`provider_call` emits
  operation count, outcome, and latency sum/count).
* **What is missing:** the harness records `prompt_tokens` / `completion_tokens`
  per case (`evaluate_model.py:143-147`) and writes them into the selection
  evidence. The product records neither, and none of its cost/status signals are
  bound to the `TemplateVersion` row. AI-010's "status/cost" criterion is met at
  the fleet-metrics level only.
* **Change that closes it:** on the internal path, capture the usage block and
  persist it into `raw_proposal` alongside the other provenance fields.

---

## Protections verified as correctly implemented

These were read and confirmed in code, not assumed:

1. **Pre-boundary neutralization of every free-text field.**
   `jobs.py:1898-2006` routes every pattern field, list item, ATT&CK mapping key
   and value, and source excerpt through `_clean` → `kp_sanitization.neutralize`
   (`packages/sanitization/src/kp_sanitization/neutralize.py:102`, with override /
   action / fake-admin instruction patterns at `:41-100`) **before** anything
   leaves the process. This is *stronger* than the harness, which deliberately
   feeds raw injection excerpts to score the model's resistance. In production the
   injected text is stripped in-process, so the model's resistance is a second
   line of defence rather than the only one. This directly answers the
   prompt-injection question: yes, and at a better layer than the harness tests.
2. **Untrusted-context signalling is carried end to end.** `context_untrusted`
   and `neutralization_reasons` go to the gateway (`generation.py:142-146`,
   `jobs.py:1989-1992`) and are persisted onto the draft for the human reviewer
   (`jobs.py:547-549`).
3. **Advisory guidance does carry the injection rule.** `jobs.py:1997-2002`
   instructs the gateway to treat every pattern field, excerpt, citation,
   indicator, actor, sector, and timestamp as untrusted data and never as
   instructions — the same rule as `evaluate_model.py:71-72`. Correctly labelled
   advisory in the contract.
4. **Outbound request is bounded and re-validated at the socket.** Per-field,
   per-list, nesting-depth and aggregate 64 KiB serialized caps
   (`generation.py:40-53, 164-168`), re-checked from a serialized round-trip
   *before* the HTTP stream opens (`jobs.py:2074-2080`), with a content-free
   error.
5. **Inbound response is bounded before parsing.** Duplicate `Content-Length`
   rejection, malformed-length rejection, declared-size rejection, and a
   cumulative streamed byte cap enforced *before* `json.loads`
   (`jobs.py:2047-2066`). Matches the harness posture and adds header hardening
   the harness lacks.
6. **Contract validation with `extra="forbid"`.** `generation.py:171-183`,
   applied at `jobs.py:2103-2106`. A gateway cannot smuggle an approval flag, a
   recipient list, a schedule, or a send instruction past the contract. The model
   proposes content and nothing else — the "no model approval/launch authority"
   criterion is genuinely enforced in code.
7. **The real training URL is never disclosed to the model.** Only the Jinja
   placeholder crosses the boundary (`jobs.py:1993-1996`,
   `generation.py:147-150`), and `apps/workers/tests/test_generation_pipeline.py`
   asserts `training_base_url` does not appear anywhere in the serialized request.
8. **Placeholder required in both bodies.** `generation.py:185-190`. Worth noting
   this is a Pydantic `model_validator` and is therefore **not** representable in
   `model_json_schema()` — so even perfect schema-constrained decoding would not
   guarantee it, and the post-hoc check is load-bearing. It is correctly present.
9. **Deterministic re-validation of model output before persistence.**
   `jobs.py:530-543` runs the full `SafetyValidator` (credential/MFA requests,
   attachments and executable extensions, command execution, software install,
   financial transfer, sensitive-employee scenarios, `javascript:` / `data:` /
   `vbscript:` URIs, QR codes, macros, hidden zero-width and bidi characters,
   external link allowlist — `validator.py:116-205, 449-510`) with the placeholder
   substituted by a trusted relative stand-in so the validator's unknown-href rule
   does not misfire. Any rejection aborts.
10. **Fail-closed, constant-time model pin.** `jobs.py:2107-2116` uses
    `secrets.compare_digest` and refuses the whole response on mismatch; managed
    generation workers cannot start without a pin (`config.py:167-171`);
    `ai_model_id` is validated as a single line without NUL/CR/LF
    (`config.py:320-321`).
11. **Hard fail, no fallback template, no partial write.** Every failure class
    raises before `session.add` at `jobs.py:558-566`. There is **no** retry with a
    relaxed prompt, **no** template fallback, and **no** path that persists
    unvalidated content. The supervisor rejects the message
    (`supervisor.py:150-169`) and the queue retries up to 3 times then dead-letters
    (`queue.py:249-272`). Answering question 3 directly: it is a hard fail with a
    bounded queue-level retry, and nothing that could persist bad content.
12. **Errors never echo provider content.** `AIRequestError` / `AIResponseError`
    messages are fixed strings with `from None`; tests assert a planted provider
    secret never appears in the raised exception.
13. **Human approval gate is real.** The draft persists as
    `TemplateApprovalState.DRAFT` (`jobs.py:568`); the requester is recorded but
    cannot self-approve, and approval re-checks canonical content
    (`apps/operator-api/tests/test_template_approval_gate.py:114-204`).
14. **Second fence at delivery.** `_delivery_template_content`
    (`jobs.py:2120-2134`) refuses approved content lacking the placeholder,
    `_contains_url` (`jobs.py:2187-2190`) refuses a static training URL in
    rendered output, and `SafetyValidator` runs again on the fully rendered,
    recipient-bound message (`jobs.py:2196-2198`).
15. **Idempotency and concurrency.** Generation is keyed on
    `idempotency_key` with a database unique constraint arbitrating concurrent
    workers (`jobs.py:571-590`), and source/pattern rows are locked in a fixed
    order so a concurrent reject/merge cannot race generation
    (`jobs.py:462-512`).

---

## Not determinable from the code

* **Whether any real `/propose` gateway exists, and how it decodes.** No
  implementation is in this repository other than the dev mock. Repository docs
  are consistent and explicit that live provider generation is unqualified
  (`README.md:129`, `docs/WAVE-BUILD-PLAN.md:311`). The audit therefore cannot say
  whether a deployed gateway does or does not apply `json_schema`; it can only say
  that nothing in the product requires or verifies it.
* **Whether the gateway's own prompt matches the harness `SYSTEM_PROMPT`.**
  `evaluate_model.py:67-75` includes the injection rule, the placeholder rule, and
  the explicit output shape. The product sends only the advisory `guidance` string
  in the request body; how a gateway maps that onto a system prompt is outside
  this tree.
* **Whether scale-to-zero hosting exists.** No hosting/lifecycle code for a model
  endpoint was found on the worker path; `RUNBOOK.md:35` describes it as the
  intended target with serverless GPU "measurement-gated". Nothing to audit yet.
* **Whether the bake-off's selected model would satisfy G4** (omitting `model_id`
  under strict decoding) — the bake-off scored schema validity, not field
  presence against a pin, and no model was run for this audit.


---

## Verification addendum (2026-08-31) — findings re-checked against the live safety layer

After the internal AI gateway (apps/ai-gateway) was built and Qwen integrated,
the audit findings were re-checked against the running SafetyValidator:

- **#5 (extra live URL beside the placeholder) is NOT exploitable as described.**
  `SafetyValidator.validate` rejects an extra URL even on the training domain: a
  proposal containing `https://training.example.com/collect` alongside the
  placeholder returns `allowed=False` ("external link not on training
  allowlist: example.com (bare-domain)"). An external link
  (`https://attacker.invalid/...`) is likewise rejected. The real Qwen output
  passes clean (`allowed=True`). No fix required.
- **#1 (no schema-constrained decoding product-side) is RESOLVED.** The gateway
  performs strict `json_schema` decoding against `GenerationResponse`.
- **#3 (pinned model_id not bound into the record) is RESOLVED at the source.**
  The gateway returns the configured pinned identity verbatim, so the recorded
  `model_id` is the pin, not the model's self-report.
- **#4 (model_id optional, "unknown" default) was fixed in the contract earlier**
  (required, min_length=1).

Residual, low priority: #2 (tool-less/network-less is enforced by the gateway
sending no tools and llama.cpp having no network egress, but there is no live
posture probe), and #7 (cost is bytes+latency, not tokens). Neither blocks the
supported inference path.
