environment        = "production"
postgres_sku       = "GP_Standard_D2ds_v5"
redis_sku          = "Balanced_B1"
log_retention_days = 30
log_daily_quota_gb = 2

# --- AI / Foundry model roles (appropriate, cost-effective token-based choices) ---
# Production must NOT inherit the gpt-oss-120b default: the redesign spec measured
# it ~20% schema-INVALID (flaky Preview). Use the same current GA/reasoning models
# staging proved, token-based GlobalStandard in Foundry (no GPU VM to host):
#   BUILD  (generation)         -> gpt-5.6-terra  (GA; rejects reasoning_effort + temperature)
#   CURATE (extraction/grounding) -> gpt-5.6-luna (reasoning=none)
# These take effect only once the production Foundry account is provisioned and
# the gateway is enabled: set ai_foundry_endpoint to the prod Foundry endpoint,
# deploy gpt-5.6-terra + gpt-5.6-luna there out-of-band
# (az cognitiveservices account deployment create), and set deploy_ai_gateway=true
# with a digest-pinned ai_gateway_image. Web-search discovery (gpt-5.6-luna +
# ai_responses_base_url) is left OFF for production: the curated vendor feeds are
# better, lower-risk grounding — enable it explicitly only if accepted.
ai_foundry_model            = "gpt-5.6-terra"
ai_reasoning_effort         = ""
ai_send_temperature         = false
ai_max_completion_tokens    = 2000
ai_extract_model            = "gpt-5.6-luna"
ai_extract_reasoning_effort = "none"
