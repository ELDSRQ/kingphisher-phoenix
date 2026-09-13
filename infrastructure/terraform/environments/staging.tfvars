environment        = "staging"
postgres_sku       = "GP_Standard_D2ds_v5"
redis_sku          = "Balanced_B0"
log_retention_days = 30
log_daily_quota_gb = 5

# Frequent anchoring in staging so a freshly-rolled worker revision can
# complete an anchor cycle and prove audit-anchor readiness within the
# worker-qualify gate window (fresh revisions reset in-memory proven_live).
audit_anchor_interval_seconds = 120

# Required: recipient allowlist (platform fails closed without it)
allowed_recipient_domains = "erikdierksgmail.onmicrosoft.com,gmail.com,floridamanevolved.us"

# Generation model (pins BOTH KP_AI_GATEWAY_MODEL_ID and the worker's
# KP_WORKER_AI_MODEL_ID via one local, so the AI-010 pin cannot drift). Moved off
# the gpt-oss-120b Preview reasoning model onto a current GA model; reasoning
# effort is bounded below so latency is controlled regardless. The deployment
# `gpt-5.6-terra` must exist in the Foundry account before this applies.
ai_foundry_model = "gpt-5.6-terra"
# Reliability config, PROVEN against gpt-5.6-terra (10/10 valid, p95 5.4s) by
# scripts/operator/ai/benchmark_generation.py:
#  - terra is a GA generation model: it REJECTS reasoning_effort (400), so leave
#    it empty (the gateway omits the field on empty via env_ignore_empty).
#  - terra REJECTS any explicit temperature (400 "only the default is supported"),
#    so omit it.
#  - a 2000-token cap keeps output bounded and generation ~4.5s.
ai_reasoning_effort             = ""
ai_send_temperature             = false
ai_max_completion_tokens        = 2000
worker_provider_timeout_seconds = 30
# P1 extraction stage: normalize threat evidence into a CampaignRecord before
# generation, for more specific, current content. PROVEN against gpt-5.6-luna
# (8/8 valid, p95 ~2.5s) by scripts/operator/ai/benchmark_generation.py --task
# extract. luna takes reasoning_effort=none and (like terra) rejects temperature;
# ai_send_temperature above already omits it for the whole managed gateway. The
# gpt-5.6-luna deployment must exist in the Foundry account (out-of-band).
ai_extract_model           = "gpt-5.6-luna"
ai_extract_reasoning_effort = "none"

# Staging matches the on-prem posture: a two-person IT team cannot field the
# three distinct identities `enforce` needs to publish. single-operator drops
# only the second approver; the allowlist stays fail-closed and everything is
# still audit-logged.
operator_approval_policy = "single-operator"
