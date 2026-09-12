# Standalone Readiness Assessment
**Date:** 2026-09-10 | **Head:** `3b8cd47` | **Deploy:** `34479747420` ✅

> **Addendum 2026-09-11** — the assessment below still holds; three
> things changed. The standalone campaign-lifecycle E2E now **passes 8/8** run by a
> single operator; a supported **`single-operator`** approval posture was added so a
> 2-person IT team is not blocked by a 3-approver control; and two real bugs that only
> ever surfaced on the standalone path were fixed (IPv4 loopback probing, audit-anchor
> provider default). See `AI_HANDOFF_2026-09-11.md` for the full picture.
> 
> **Addendum 2026-09-11 (end of session)** — Azure live E2E is gated by
> a Terraform apply that is **blocked on Azure provider auth (403 on
> management.azure.com)** while the `az` CLI itself works. DMARC for
> `mail.floridamanevolved.us` is in place.
>
> An earlier version of this addendum listed `OPERATOR_API_AUDIT_HMAC_KEY` and
> `KP_WORKER_AUDIT_HMAC_KEY` among the missing env vars. **That was wrong** — `audit-hmac`
> is the audit signing root, held by the migration identity only, and granting it to the
> operator or workers fails
> `test_audit_signing_root_is_exposed_only_to_migration_identity`. The pending changes are
> `recipient-import-digest` in the operator's container `secret` block (completing
> `3ea6fb5`) and `allowed_recipient_domains` in staging tfvars.

---

## 1. Is a Process in Place to Prevent the 409 Loop?

**Yes — two layers of defense:**

### Layer 1: Terraform State Consistency (Primary)
- **Root cause fixed:** The two orphaned `workload_secret` role assignments at the Key Vault secret scope (`ai-gateway-auth-key`) were the root cause. They were deleted from Azure (`az role assignment delete --ids <id>`) and the successful deploy re-created them in terraform state.
- **Guardrail:** The workflow now has a pre-apply cleanup step (`Clean up any existing Foundry role assignment for the gateway`) that deletes any existing `azurerm_role_assignment.workload_secret["ai-gateway:..."]` and `workload_secret["worker:ai-gateway-auth-key"]` before `terraform apply`. This ensures a clean slate on every deploy.

### Layer 2: Terraform Lifecycle (Secondary)
- Added `lifecycle { ignore_changes = [principal_id, role_definition_name] }` to `azurerm_role_assignment.ai_gateway_foundry_user` — harmless but documents intent.

### Gap: Local Terraform State Access
- **Known gap:** Local terraform state access requires valid SAS token (expires in 2h). CI runner has OIDC; local dev needs `terraform init -reconfigure` with fresh SAS.
- **Mitigation:** All state mutations happen in CI; local terraform is read-only for planning.

---

## 2. Has Too Much Been Removed from Azure?

**No — the environment is complete and healthy.**

### Current Azure Resources (staging)
```
✅ Container Apps (4): operator, tracking, worker, ai-gateway — all Running
✅ PostgreSQL Flexible Server (psql-kp-staging-6117w) — Running
✅ Key Vault (kvkpstaging6117w) — with all secrets intact
✅ Redis (private endpoint) — Running
✅ Container Apps Environment (cae-kp-staging) — healthy
✅ ACS Email Service (email-kp-staging-6117w) — domain verified, sender configured
✅ Key Vault (audit_anchor_secret) — intact
✅ Private Endpoints (6): postgres, redis, vault, acr, audit-anchor, blob
✅ Private DNS zones linked
✅ Container Apps Environment (cae-kp-staging) with internal load balancer
✅ Log Analytics workspace (log-kp-staging)
```

**Nothing essential was over-deleted.** The only orphaned resources were the two per-secret Key Vault role assignments — now deleted and re-created cleanly by the successful deploy.

### What Was Correctly Removed (Intentional)
| Resource | Reason |
|---|---|
| `azurerm_container_app.ai_gateway` (old revision) | Replaced by new deployment with Foundry backend |
| `azurerm_role_assignment.workload_secret["ai-gateway:ai-gateway-auth-key"]` | Orphaned from state surgery; deleted, recreated cleanly |
| `azurerm_role_assignment.workload_secret["worker:ai-gateway-auth-key"]` | Orphaned from state surgery; deleted and recreated |

---

## 3. Can This Run Fully Independent of Azure/Entra?

**Yes.** (The earlier gpt-oss-120b structured-output caveat is resolved — see the AI Model note below and `docs/AI_PIPELINE_REDESIGN_SPEC.md`.)

### Standalone Mode (`KP_PROFILE=local-dev` or `local-hardened`)
| Component | Azure Dependency | Standalone Replacement | Status |
|-----------|------------------|------------------------|--------|
| **Compute** | Container Apps | Docker Compose (same images) | ✅ `docker-compose.standalone.yml` exists |
| **Database** | Azure Flexible Postgres | `postgres:16-alpine` in compose | ✅ Same image, `bootstrap_local_parity.py` grants parity |
| **Queue/Cache** | Azure Redis | `redis:7-alpine` in compose | ✅ Same `redis://` URL |
| **Email Transport** | ACS | SMTP relay (Postfix/OpenDKIM) + Mailpit dev | ✅ Phase 4 ready |
| **Identity** | Entra OIDC | Keycloak (landed in `infrastructure/idp/`) | ✅ Landed, contract-tested |
| **Directory Sync** | Entra ID (Graph) | Keycloak sync provider (Phase 3) / LLDAP | Phase 3 |
| **Reported Mailbox** | M365 Graph | IMAP provider (Phase 3) + Dovecot | Phase 3 |
| **Receipts** | Event Grid → ACS | SMTP DSN + relay webhook (Phase 4) | Phase 4 |
| **Audit Anchor** | Azure Blob (locked, WORM) | `local_worm` today; MinIO Object Lock (compliance mode) | ✅ local_worm / Phase 5 for MinIO |
| **Secrets** | Key Vault references | `.env` (dev) / SOPS+age / Vault (Phase 2) | Phase 2 |
| **AI Backend** | Foundry Serverless (D-0001) | llama.cpp + ai-gateway (local) | ✅ **Already working** |
| **AI Model** | `gpt-5.6-terra` (Foundry, pay-per-token) | bounded local Qwen2.5 (llama.cpp) | ✅ **Resolved** (see below) |

### AI Model Structured Output — RESOLVED (P0, PR #1, 2026-09-12)
The earlier "gpt-oss-120b quality risk" is fixed. The real cause was **unbounded reasoning effort** (generation ran past the worker timeout), and gpt-oss-120b is a flaky *Preview* model (~20% schema-**invalid** — truncated/invalid JSON; not "reasoning-channel text in fields": the `content` field is valid JSON and the gateway ignores the separate `reasoning_content` channel).
- **Azure:** pinned to **`gpt-5.6-terra`** (current GA model) with reasoning empty, temperature omitted, and a `max_completion_tokens` cap. Benchmarked 10/10 schema-valid, p95 ~5.4s, zero timeouts (`scripts/operator/ai/benchmark_generation.py`). **Not** `gpt-4.1-mini` — that earlier suggestion is superseded.
- **Standalone/local:** the gateway now bounds the local Qwen output (`KP_AI_GATEWAY_MAX_COMPLETION_TOKENS`, sent as `max_tokens`); the deterministic `SafetyValidator` rejects unsafe output and a human approves every draft. The planned P2 HTML allow-list sanitizer (see `docs/AI_PIPELINE_REDESIGN_SPEC.md`) further hardens the local path.

### What Works Fully Standalone Today
| Capability | Status |
|---|---|
| Operator console (login, campaign CRUD, recipient CSV import) | ✅ |
| Campaign creation, preview, approval (ENFORCE two-person) | ✅ |
| Full campaign lifecycle run by ONE operator (`single-operator`) | ✅ E2E 8/8 (2026-09-11) |
| Tracking API (open/click pixel, training pages) | ✅ |
| Worker roles (ingestion, delivery, retention, reminder, etc.) | ✅ |
| Audit anchor chain (local_worm or MinIO Object Lock) | ✅ |
| Mailpit email sink (dev) / Postfix+DKIM relay (prod) | ✅ |
| Keycloak OIDC login (Entra-compatible roles) | ✅ |
| Audit chain verification (HMAC + append-only) | ✅ |

---

## 4. Process to Prevent Recurrence

| Guardrail | Status |
|---|---|
| **Pre-apply cleanup step** in workflow (deletes orphaned role assignments) | ✅ Deployed |
| **Terraform lifecycle** `ignore_changes` on Foundry role assignment | ✅ (harmless but documented) |
| **Pre-apply cleanup step** in workflow deletes orphaned role assignments | ✅ Deployed |
| **Digest re-pin enforced** | Manual (3× missed this session) — could add CI check |
| **State surgery checklist** | Not yet documented — **action item** |

---

## 4. What Remains to Reach "Campaign Ready"

| Task | Phase | Effort | Blockers |
|---|---|---|---|
| Recipients CSV import + preview | Phase 1 | ✅ API ready; console UI exists | Need operator auth (Entra/Keycloak) |
| Canary send to test mailbox | Phase 1 | ✅ ACS verified | Need test mailbox |
| DMARC record for `mail.floridamanevolved.us` | Phase 4 | Optional for ACS; improves deliverability | DNS access |
| ~~gpt-oss-120b quality gate~~ | ✅ Done (P0) | Resolved: bounds + `gpt-5.6-terra` (Azure); bounded Qwen (local). See `docs/AI_PIPELINE_REDESIGN_SPEC.md` | — |
| Phase 3: IMAP provider + Keycloak sync | Phase 3 | ~2 weeks | — |
| Phase 4: Postfix+DKIM relay + SMTP receipts | Phase 4 | ~2 weeks | DNS access |
| Phase 5: MinIO Object Lock + S3 audit anchor provider | Phase 5 | 1-2 weeks | Separate volume/host for compliance |

---

## TL;DR for Next Session

| Question | Answer |
|---|---|
| **Process to prevent 409 loop?** | ✅ Pre-apply cleanup step deletes orphaned role assignments; terraform lifecycle on Foundry assignment |
| **Too much removed from Azure?** | No — environment is complete and healthy; only orphaned role assignments were cleaned up |
| **Fully standalone capable?** | **Yes.** The gpt-oss-120b structured-output caveat is resolved (P0, PR #1): Azure uses `gpt-5.6-terra`; the local path uses bounded Qwen with human approval. See `docs/AI_PIPELINE_REDESIGN_SPEC.md`. |
| **Ready for campaign?** | Infrastructure ✅. Next: recipients CSV → canary send → launch. |

**Recommendation:** Proceed to recipients import → canary send → launch. The infrastructure is solid.

---

## Addendum detail — 2026-09-11

### Standalone-only bugs found and fixed
Both were invisible on Azure and blocked the standalone E2E:

- **IPv4 loopback probing** (`4b59812`). `_resolve_pinned_target` validated every DNS
  answer then pinned `resolved[0]`. On a dual-stack host `localhost` resolves to `::1`
  first, but tunnels and Docker bind IPv4 only, so the console reported the identity and
  AI connectors as *failing configuration* when curl reached them fine.
- **Audit-anchor provider default** (`656b3e2`). The worker defaults to `azure_blob`;
  without `KP_WORKER_AUDIT_ANCHOR_PROVIDER=local_worm` it never became ready, and the
  operator API then refused every privileged change with `audit_integrity_unhealthy` —
  surfacing as unexplained 503s on campaign creation and directory sync.

### Divergence worth watching
The standalone `.env` hands the operator API the audit HMAC key; the managed posture
deliberately does **not** (API replicas stage intent only). That difference masked a real
defect — recipient import reached for the audit signing root and 500'd on Azure only.
Fixed in `3ea6fb5` by giving the import digest its own key. **When a capability works
standalone but not on Azure, suspect the standalone posture is the weaker one.**

### Approval posture
`single-operator` is now the supported small-team posture: it drops the second approver
and nothing else. It does **not** unlock the empty-allowlist allow-all that `SINGLE_ADMIN`
does — the recipient-domain control still fails closed. `ENFORCE` remains the default.

