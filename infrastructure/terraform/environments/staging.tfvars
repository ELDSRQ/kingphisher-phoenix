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

# Staging matches the on-prem posture: a two-person IT team cannot field the
# three distinct identities `enforce` needs to publish. single-operator drops
# only the second approver; the allowlist stays fail-closed and everything is
# still audit-logged.
operator_approval_policy = "single-operator"
