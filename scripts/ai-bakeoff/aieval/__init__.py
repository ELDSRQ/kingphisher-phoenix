"""W3-04 AI quality / privacy / cost evaluation harness (KP-AUD-010/012 + Report-04).

Additive, offline, deterministic. This package measures AI proposals against the
W3-01 deterministic cue ontology (the ground truth), compares model-free, local,
and hosted options from MOCK-RECORDED fixtures (no live provider calls), records
per-provider usage/circuit telemetry carrying no prompt or completion content,
and encodes the default-local / explicit-hosted-acknowledgement egress posture.

Nothing here edits or imports the AI gateway's request path; it reads the shared
contracts (``kp_contracts.cue_ontology``, ``kp_contracts.generation``,
``kp_contracts.discovery``) and the operator provider registry
(``kp_operator_api.ai_providers``) as data.
"""

from __future__ import annotations

EVAL_HARNESS_VERSION = "w3-04-ai-eval/1"
