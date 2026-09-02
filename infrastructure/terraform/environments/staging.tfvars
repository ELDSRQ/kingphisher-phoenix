environment        = "staging"
postgres_sku       = "GP_Standard_D2ds_v5"
redis_sku          = "Balanced_B0"
log_retention_days = 30
log_daily_quota_gb = 10

# Frequent anchoring in staging so a freshly-rolled worker revision can
# complete an anchor cycle and prove audit-anchor readiness within the
# worker-qualify gate window (fresh revisions reset in-memory proven_live).
audit_anchor_interval_seconds = 120
