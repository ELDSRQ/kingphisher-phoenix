# Hybrid Azure ↔ local Docker plan (cost reduction, with a path to fully-local)

**Status:** plan + Path-B implementation (data-plane gating). Written 2026-09-05.
**Scope:** this repo only. Terraform lives in `infrastructure/terraform/`.

## Why
Azure costs are significant and dominated by *always-on* infrastructure, while the
platform **already runs entirely in Docker locally** for dev/e2e (`docker-compose.yml`:
postgres, redis, mailpit, otel, mock-idp/graph/ai, optional real ai-gateway). The only
things that genuinely require Azure are the pieces of a **real** end-to-end send.

## The three tiers

| Tier | Where | Idle cost | Contents |
|---|---|---|---|
| **1. Real-send slice** | Azure, persistent | **~$0** (ACS is per-message; domain/DNS/Entra are ~free) | ACS Communication + Email + **verified domain** + **public DNS** + **Entra app**. Optionally Key Vault. |
| **2. Compute + data** | Azure, on-demand | **$0 when idled/destroyed** | 4 Container Apps + migration job, **PostgreSQL**, **Redis**, **ACR**, Storage (audit anchor), Event Grid receipts, (starter) networking, CI runner. |
| **3. Dev/test** | Local Docker, permanent | $0 | Full compose stack with mocks. Where ~all engineering + testing happens. |

Tier 1 is cheap-to-keep, so the **verified ACS domain/DNS is never torn down** — that is
the one part of a round-trip that is painful to rebuild (SPF/DKIM re-verification;
Namecheap purge risk). Tier 2 is the real cost and is disposable because its state
(DB schema + seed) is reproducible via alembic + `scripts/seed.py`.

## The toggles (all in `infrastructure/terraform/`)

| Component | Variable / local | Persistent (Tier 1) | On-demand (Tier 2) |
|---|---|---|---|
| ACS Comm/Email/domain | `acs_resource_mode` | `"provision"` | `"existing"` + `acs_existing_*` (point at Tier 1) |
| ACS DNS records | `acs_dns_zone_id` → `local.acs_dns_automation` | set | unset |
| App tier (Container Apps + migration) | `deploy_workloads` | `false` | `true` |
| **Freely-destroyable data infra — ACR + managed Redis** | **`deploy_data_plane` (Path B, NEW)** | **`false`** | **`true`** |
| PostgreSQL | (not gated — `prevent_destroy`) | idle via `az postgres flexible-server stop` (retains data) | running |
| Audit-anchor storage | (not gated — locked WORM) | retained (small cost; irreversible by design) | retained |
| ai-gateway | `deploy_ai_gateway` | `false` | `true` (or keep local llama.cpp) |
| Event Grid receipts | `enable_acs_event_subscription` (needs `deploy_workloads`) | `false` | `true` |
| Private networking (~19 resources) | `network_mode` → `local.private_network` | n/a | `"starter"` (public+firewall, far cheaper) |
| CI runner VM | `deploy_ci_runner` | `false` | `false` (CI runs locally) |
| HA/geo sizing | `environment` | — | non-`production` |

### Path B — what the code change adds (implemented alongside this doc)
Before Path B, `deploy_workloads=false` still created Postgres, Redis, ACR, and Storage
unconditionally. Path B adds a `deploy_data_plane` flag (default **`true`**, so current
behavior is unchanged) that gates the **freely-destroyable** expensive infra — the
**Premium container registry** and **Enterprise managed Redis** — plus their private
endpoints, the `redis-url` Key Vault secret, and the ACR-pull role assignment. Setting
`deploy_data_plane=false` idles those to ~$0. A variable validation enforces that
`deploy_workloads=true` requires `deploy_data_plane=true` (workloads need the registry and
cache). `moved {}` blocks migrate existing ACR/Redis state to the new `[0]` index so
enabling the flag never proposes a destroy/recreate.

**Why NOT Postgres/Storage:** PostgreSQL carries `lifecycle { prevent_destroy = true }`
and the audit-anchor storage container is `locked = true` WORM — both are deliberately
un-destroyable to protect data/evidence. Gating them with `count` would fight those
guards. So Postgres is idled by **stopping** it (`az postgres flexible-server stop` —
retains data, saves compute, ~7-day auto-restart), and the audit storage is retained
(Standard LRS blob is cheap; its immutability is the point).

> **Operator gate (this is production infra):** `terraform validate` + `fmt` are clean
> for the default (`deploy_data_plane=true`) path — which is byte-for-byte the current
> behavior except the ACR/Redis state moves to `[0]` (handled by the `moved` blocks). The
> **idle path (`deploy_data_plane=false`) has NOT been `plan`-verified** (no Azure state
> here). Before first use, run `terraform plan` with `deploy_data_plane=false` and confirm
> it proposes destroying **only** the registry + Redis (+ their PEs/role/secret) and
> **nothing else** — especially no Postgres/Storage destroy.

## Operating workflow
1. **Day-to-day:** local Docker only (`make dev` / compose e2e). No Azure spend.
2. **Real send:** `terraform apply` with `deploy_workloads=true, deploy_data_plane=true,
   network_mode=starter, acs_resource_mode=existing (→ Tier 1), enable_acs_event_subscription=true,
   deploy_ci_runner=false` → re-patch OIDC env → migrate + seed → send.
3. **After:** `terraform apply` with `deploy_workloads=false, deploy_data_plane=false`
   (destroys Container Apps + ACR + Redis), then **stop Postgres**:
   `az postgres flexible-server stop -g <rg> -n <server>` (retains data, ~7-day
   auto-restart). Tier 1 (ACS/domain/DNS) stays up at ~$0; the next send skips all ACS
   re-verification, and starting Postgres + re-applying the flags brings the rest back.

## Cost levers, ranked
1. `deploy_workloads=false` — drops the always-on Container Apps replicas (operator/
   tracking never scale to zero).
2. **Stop Postgres** (`az postgres flexible-server stop`) — removes the D2ds_v5 compute
   charge while retaining data. The single biggest lever; it's an ops action, not a flag,
   because Postgres is `prevent_destroy`.
3. `deploy_data_plane=false` — drops the Premium ACR + Enterprise Redis (Path B).
4. `network_mode="starter"` — drops 5 private endpoints + NAT gateway + public IP + 5
   private DNS zones (hourly-billed) even while Tier 2 is up.
5. `deploy_ci_runner=false` — drops the always-on CI VM (CI runs on the local `.105` worker).
6. non-`production` `environment` — no ZoneRedundant HA / geo-redundant backup.

## Phase 3 — fully local when the O365/Entra subscription expires
When O365/Entra lapses you lose **real Entra OIDC** (operator SSO) and the ACS tie. At that
point Azure goes to **zero** and the platform runs entirely in Docker. The seams for this
already exist; the scaffolding is configuration, not a rewrite:

- **Identity:** the app's auth-mode discovery is configurable and *fails closed*. Local
  options: (a) `mock-idp` (dev-auth, already in compose) for internal/testing use, or
  (b) a self-hosted OIDC issuer in Docker (Keycloak/Dex/Authentik) pointed at by the same
  `OPERATOR_API_OIDC_*` config that today names Entra — a drop-in issuer swap, no code
  change. This is the recommended real-but-local identity path.
- **Email:** the provider abstraction already offers **SMTP vs ACS** (GUI select;
  `KP_WORKER_SMTP_ADDRESS`). Fully-local real delivery uses an SMTP relay instead of ACS;
  `mailpit` remains the non-delivering local sink for training/testing.
- **Everything else** (app, Postgres, Redis, telemetry, CI) is already local in Tier 3.
- **Terraform:** fully-local = simply never apply Tier 2/1. Path B's gating means the
  Azure footprint can be driven to nothing without deleting the config, so re-enabling
  Azure later is a flag flip, not a rebuild.

**Net:** Path B makes idle Azure cost ~$0 today (keeping only the real-send slice), and
the same flag structure + the SMTP/OIDC-issuer seams make a later "no Azure at all"
posture a configuration switch rather than a migration.
