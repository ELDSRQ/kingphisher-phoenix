# Azure residency audit — what is local, what is not, and why (2026-09-07)

**Type:** audit. Read-only. No Azure resource was created, changed, started, stopped or
destroyed; no `terraform apply` and no `gh workflow run` was issued. Every `az` call was a
read. The local WSL2 host (`erikd@192.168.1.105`) was inspected read-only over ssh; no
container there was started, stopped or modified.

**Scope:** every component of the platform, answering two questions:

1. Has everything that *can* run locally — without hurting the build, its speed, or a real
   feature — actually *been* moved local?
2. For each component still in Azure: is it there because no on-premises equivalent exists,
   or merely by inertia?

**Headline answer, and it is not the one the existing docs give.**

The application has genuinely moved local: operator-api, tracking-api, eight workers,
Postgres, Redis, Mailpit, OTel and Qwen2.5-7B all run on `.105` today and were observed
healthy. That part of the story is true.

But **Azure is not idled.** On 2026-09-06, the last full billing day, `rg-kp-staging` cost
**$35.70** — an annualised run-rate of **~$1,085/month**, *higher* than the "~$800/mo before
idling" figure the docs use as the baseline they claim to have escaped. **$29.24 of that
$35.70 (~$889/mo, 82%)** is a single defect nobody has noticed: the `operator` and `tracking`
Container Apps run in `Multiple` revision mode and have accumulated **76 orphaned active
revisions**, each holding one replica wedged in `Activating`, each billed as idle vCPU and
memory, forever. Scaling the app to `min-replicas 0` — which is what both the manual idle and
the armed nightly job do — **does not touch them**, and the nightly job in fact skips the apps
entirely because the app-level minimum already reads `0`.

So the honest verdict on question (1) is: *the application moved, the Azure bill did not.*

---

## 1. Ground truth

### 1.1 What actually exists in Azure

`az resource list -g rg-kp-staging` (2026-09-07) returns 49 resources: 4 Container Apps + 1
job, a Container Apps environment, PostgreSQL Flexible Server, Redis Enterprise, a Premium
ACR, Key Vault, an audit-anchor storage account, App Insights + Log Analytics, ACS +
Email Service + the verified domain `mail.floridamanevolved.us`, an Event Grid system topic
and subscription, 5 user-assigned identities, a VNet, **the CI-runner VM with its NAT gateway,
public IP, NSG and NIC**, and **5 private endpoints + 5 private DNS zones**.

### 1.2 Measured cost — Azure Cost Management, not estimates

`POST .../Microsoft.CostManagement/query`, ActualCost, filtered to `rg-kp-staging`.

Daily, USD:

| Service | 09-01 | 09-02 | 09-03 | 09-04 | 09-05 | 09-06 | 09-07\* |
|---|---|---|---|---|---|---|---|
| Azure Container Apps | 0.00 | 1.77 | 17.94 | 23.61 | **32.31** | **30.63** | 17.03 |
| Azure Database for PostgreSQL | 1.78 | 4.27 | 4.27 | 4.27 | 4.27 | 0.18 | 0.00 |
| Virtual Machines | 0.14 | 3.16 | 3.17 | 3.17 | 3.17 | 0.04 | 0.00 |
| Container Registry | 0.73 | 2.34 | 2.35 | 2.11 | 1.82 | 1.67 | 0.97 |
| Virtual Network (private endpoints) | 0.00 | 0.72 | 1.36 | 1.34 | 1.33 | 1.32 | 0.81 |
| NAT Gateway | 0.04 | 1.36 | 1.19 | 1.14 | 1.11 | 1.08 | 0.68 |
| Redis Cache | 0.17 | 0.38 | 0.38 | 0.38 | 0.38 | 0.38 | 0.22 |
| Azure DNS (private zones) | 0.00 | 0.04 | 0.08 | 0.08 | 0.08 | 0.33 | 0.21 |
| Storage | 0.00 | 0.05 | 0.08 | 0.07 | 0.07 | 0.05 | 0.03 |
| Key Vault | 0.00 | 0.01 | 0.02 | 0.01 | 0.01 | 0.01 | 0.00 |
| Log Analytics | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| **TOTAL** | 2.85 | 14.12 | 30.85 | 36.19 | **44.55** | **35.70** | 19.95 |

\* 09-07 is a partial day (query taken ~19:50 UTC).

Two things to notice. **Communication Services never appears** — Tier 1 (ACS, the verified
domain, Event Grid, Entra) really is ~$0, exactly as the plans claim. And **2026-09-05, the
day `docs/LOCAL-FIRST-MIGRATION-PLAN.md` records as the "immediate cost stop", was the single
most expensive day in the window.**

### 1.3 The $889/month defect

Cost by resource + meter, 09-06 → 09-07 (2 days), USD:

```
 16.384  Standard Memory Idle Usage    containerapps/ca-kp-staging-operator
 13.986  Standard Memory Idle Usage    containerapps/ca-kp-staging-tracking
  8.192  Standard vCPU Idle Usage      containerapps/ca-kp-staging-operator
  6.993  Standard vCPU Idle Usage      containerapps/ca-kp-staging-tracking
  2.639  Premium Registry Unit         registries/acrkpstaging
  1.755  Standard Gateway              natgateways/nat-kp-staging-runner
  1.574  Standard vCPU Active Usage    containerapps/ca-kp-staging-worker
  0.608  B0 Cache Instance             redisenterprise/redis-kp-staging-6117w
  0.390  Standard Private Endpoint     privateendpoints/pep-kp-staging-{acr,audit-anchor,redis,vault}  (each)
  0.380  Standard Private Endpoint     privateendpoints/pep-kp-staging-postgres
  0.178  vCore                         flexibleservers/psql-kp-staging-6117w   (stopped; storage only)
```

Usage quantities pin down the mechanism. On 09-06 the `operator` app billed **1,752,750
vCPU-seconds** and **3,505,500 GiB-seconds** of *idle* usage — 20.3 vCPU and 40.6 GiB running
continuously. `tracking` billed 17.3 vCPU / 34.6 GiB. Both apps are configured
`cpu: 0.5, memory: 1Gi`, `maxReplicas: 3`.

The reconciliation:

```
$ az containerapp revision list -g rg-kp-staging -n ca-kp-staging-operator
  revisions total=42  active=42  sum_replicas_on_active=41
  runningState: {'Activating': 41, 'ActivationFailed': 1}
  oldest active: 2026-09-02T11:54:33Z   newest: 2026-09-06T00:18:18Z

$ az containerapp revision list -g rg-kp-staging -n ca-kp-staging-tracking
  revisions total=36  active=36  sum_replicas_on_active=35
  runningState: {'Activating': 35, 'ActivationFailed': 1}

$ az containerapp list -g rg-kp-staging --query "[].{n:name,mode:...activeRevisionsMode,min:...minReplicas}"
  ca-kp-staging-operator     Multiple  0
  ca-kp-staging-tracking     Multiple  0
  ca-kp-staging-worker       Single    0
  ca-kp-staging-ai-gateway   Single    0
```

41 × 0.5 vCPU = 20.5 vCPU and 41 GiB for `operator`; 35 × 0.5 = 17.5 vCPU and 35 GiB for
`tracking`. That is the billed quantity, to within rounding.

A sample stuck replica:

```
$ az containerapp replica list ... --revision ca-kp-staging-operator--0000040
  replica ...-xn6t8  runningState=Running
     container operator  ready=False  started=True  restarts=0
     "Container started at: 9/5/2026 2:23:06 PM."
```

The container starts, never becomes *ready* (its dependencies — Postgres is stopped, the data
plane is behind private endpoints — are unreachable), and Container Apps parks it in
`Activating` indefinitely, billing it at the idle rate. Because `restartCount` is 0 there is
no crash-loop backoff to eventually give up.

**Root cause, in Terraform:**

- `infrastructure/terraform/main.tf:1299` — operator: `revision_mode = "Multiple"`
- `infrastructure/terraform/main.tf:1447` — tracking: `revision_mode = "Multiple"`
- `main.tf:1344`, `main.tf:1479` — `min_replicas = local.production ? 2 : 1` (so **1** in staging)
- `main.tf:1172` (ai-gateway) and `main.tf:1528` (worker) — `revision_mode = "Single"`, which
  is exactly why those two apps have **one** revision each and are not affected.

In `Multiple` mode every deploy creates a new revision and **leaves the previous one active
with its own scale settings**. `gh run list --workflow azure-deploy.yml` shows 15 deploy runs
between 09-03 and 09-05 alone; 42 revisions accumulated over four days. Nothing in the repo
deactivates old revisions.

**Why neither idle mechanism catches it.** `scripts/operator/azure-nightly-shutdown.sh` reads
the *app-level* minimum and short-circuits — `azure-nightly-shutdown.sh:306`:

```sh
      log "SKIP $name — already at min-replicas 0"
```

and its `az` allowlist (`azure-nightly-shutdown.sh:155`) permits only
`containerapp update * --min-replicas 0`, so it *cannot* deactivate a revision even if it
wanted to. The app-level template minimum applies to the revision a change *creates*; the 76
already-active revisions keep the `min_replicas = 1` they were born with. The nightly job is
armed (`gh variable list` → `NIGHTLY_AZURE_SHUTDOWN = enabled`) and ran green today, and it
did nothing about $29/day.

The **fix** is one read-only-to-verify, one write-to-apply: deactivate every non-current
revision on the two apps (`az containerapp revision deactivate`), and change
`revision_mode` to `"Single"` at `main.tf:1299` and `main.tf:1447` so it cannot recur. That is
**not** done here — this is an audit and Azure must stay untouched.

### 1.4 What actually runs locally

`ssh erikd@192.168.1.105 "wsl -e bash -s" < probe.sh`, 2026-09-07:

- Compose (project `phishing-awareness-platform`): `postgres:16-alpine` (:5432, healthy),
  `redis:7-alpine` (:6379, healthy), `axllent/mailpit:v1.20` (:1025/:8025, healthy),
  `otel/opentelemetry-collector-contrib:0.107.0` (:4317/:4318), `mock-idp` (:8443),
  `mock-graph` (:8181), `mock-ai` (:8282), `ai-gateway` (:8090, healthy).
- `kp-llama` (`ghcr.io/ggml-org/llama.cpp:server`) on :18081, `/health` → `{"status":"ok"}`.
  Qwen GGUF shards staged: 4.41 GB + 0.69 GB.
- Native processes, uptime 1d18h: `kp-operator-api` (:8000, `/healthz` 200),
  `kp-tracking-api` (:8001, `/healthz` 200), and **eight** `kp-worker` processes —
  `alert, delivery, directory, generation, ingestion, mailbox, reminder, retention`.
- `ai-gateway` `/readyz` → `{"status":"ready"}`; local Postgres database is 15 MB.
- Config: `OPERATOR_API_OIDC_MODE=dev`, `KP_WORKER_EMAIL_PROVIDER=smtp`,
  `KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090`,
  `KP_WORKER_AI_MODEL_ID=llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M`, `KP_DEV_STACK=1`.

Two caveats that matter for anything claimed about the local stack:

- `/root/kingphisher-phoenix` is **not a git repository** (`git log` → `fatal: not a git
  repository`). It is a copy and may lag committed HEAD. Any claim of the form "the local
  stack proves the code at HEAD works" is therefore weaker than it looks.
- The **audit-anchor worker is not running**, no `KP_WORKER_AUDIT_ANCHOR_*` variable is set in
  `.env`, and `data/audit-anchors/` does not exist. See §3.4.

---

## 2. Component verdicts

Verdicts are exactly the four requested. "Saving" is measured $/month derived from the
09-06 daily figure × 30.4, not a list-price guess, unless marked *(est.)*.

| # | Component | Azure resource | Verdict | Evidence | Effort → saving |
|---|---|---|---|---|---|
| 1 | operator-api (console) | `ca-kp-staging-operator` | **ALREADY-LOCAL** (app) / the Azure copy is **MOVABLE-NOT-YET-MOVED** | `kp-operator-api` on `.105:8000`, `/healthz` 200, 1d18h uptime. Azure copy: 42 active revisions, 41 stuck `Activating` | Deactivate revisions + `revision_mode="Single"` (`main.tf:1299`); ~2h incl. plan review → **$480/mo** |
| 2 | tracking-api | `ca-kp-staging-tracking` | **ALREADY-LOCAL** (app) / Azure copy **MUST-STAY-FOR-NOW** *only during a real send* | `kp-tracking-api` on `.105:8001`, `/healthz` 200. Azure: 36 revisions, 35 stuck | Same fix → **$409/mo**. A real send needs a public HTTPS click/open endpoint; that need is public-internet, not Azure-specific |
| 3 | workers (8 roles) | `ca-kp-staging-worker` | **ALREADY-LOCAL** | 8 `kp-worker` processes on `.105`. Azure app: 1 revision, `RunningAtMaxScale`, 0.5 vCPU/1 GiB, running since 09-06T00:19 | `deploy_workloads=false` (already written in `environments/idle.tfvars`) → **$38/mo** |
| 4 | ai-gateway | `ca-kp-staging-ai-gateway` | **ALREADY-LOCAL** | compose `ai-gateway` :8090 `/readyz` ready; Azure revision `ScaledToZero`, 09-06 cost $0.12 | already effectively free |
| 5 | AI model serving (Qwen) | — (no Azure resource) | **ALREADY-LOCAL** | `kp-llama` :18081 healthy, Qwen2.5-7B Q4_K_M staged (5.1 GB). The Azure ai-llama sidecar has already been dropped per D-0001 | $0 — the 09-05 ai-gateway spike ($3.11 that day, 4 vCPU/8 GiB idle) is already gone |
| 6 | PostgreSQL | `psql-kp-staging-6117w` | **MOVABLE-NOT-YET-MOVED**, but *keep* | `state: Stopped`; local `postgres:16-alpine` serves all dev/test (15 MB db). Storage-only charge $0.18/day. `lifecycle { prevent_destroy = true }` (`main.tf:740`) | Leave stopped. Residual **$5.5/mo** is the price of retaining real-send state; destroying it is not worth it |
| 7 | Redis | `redis-kp-staging-6117w` (Enterprise `Balanced_B0`) | **MOVABLE-NOT-YET-MOVED** | `resourceState: Running`, `redisVersion 7.4`. Local `redis:7-alpine` runs. Gated by `deploy_data_plane` (`main.tf:765`) — a flag written on 2026-09-05 and **never set false** | `deploy_data_plane=false` → **$11.6/mo** |
| 8 | Container registry | `acrkpstaging` (Premium) | **MOVABLE-NOT-YET-MOVED** | 10.13 GB stored (`az acr show-usage`). Local builds never pull from it. Premium is required only because `pep-kp-staging-acr` exists — Premium is the only SKU that supports Private Link | `deploy_data_plane=false` → **$50.8/mo**; or keep images and drop to Standard under `network_mode="starter"` → ~**$30/mo** |
| 9 | ACS + Email Service + verified domain | `acs-…`, `email-…/mail.floridamanevolved.us` | **MUST-STAY-AZURE** | See §3.1. Verification states all `Verified` (Domain/SPF/DKIM/DKIM2). **Cost: $0** — Communication Services does not appear in any cost row | keep — it is free and it is the only thing here that is genuinely hard to rebuild |
| 10 | Public DNS for the sending domain | *(none — not in Azure)* | **ALREADY-LOCAL / not Azure** | `dig NS floridamanevolved.us` → `pdns1/pdns2.registrar-servers.com` (Namecheap). `az network dns zone list` returns empty. `acs_dns_zone_id` is unset, so `local.acs_dns_automation` is false and Terraform manages no records | $0. The Namecheap "Email Forwarding purges records" trap remains the operational risk |
| 11 | Event Grid delivery receipts | `evgt-kp-staging-acs-delivery` + `acs-delivery-receipts` | **MUST-STAY-FOR-NOW** (bound to ACS) | See §3.3. Gated `var.deploy_workloads && var.enable_acs_event_subscription` (`main.tf:544`); webhook points at the operator Container App FQDN (`main.tf:554`) | $0. Blocked by a DB `CHECK (provider IN ('acs'))`, not by Azure |
| 12 | Entra / OIDC identity | Entra app (external to the RG) | **MUST-STAY-FOR-NOW** for a managed posture; **not used locally at all today** | `.105` runs `OPERATOR_API_OIDC_MODE=dev` (HS256 shared secret) — real OIDC is not exercised locally. See §3.2 | $0. Effort to swap: public hostname + publicly-trusted TLS, ~1–2 days, *not* "config only" |
| 13 | Microsoft Graph (directory sync, reported mailbox) | Graph (external) | **MUST-STAY-AZURE** unless a new provider is written | `providers/graph.py:23-24` pins `graph.microsoft.com` + `ManagedIdentityCredential`; roster key is `DirectoryUser.entra_id`; `providers/microsoft365.py:129-132` reads the reported-phish mailbox via Graph delta. Keycloak has no equivalent | $0. Replacing it = a new LDAP/SCIM/CSV directory provider + an IMAP mailbox provider. Days, not hours |
| 14 | Key Vault | `kvkpstaging6117w` | **MOVABLE-NOT-YET-MOVED**, but *keep* | Standard SKU, RBAC, public access Disabled. Local uses `.env`. 09-06 cost $0.01 | **$0.3/mo** — not worth touching |
| 15 | WORM audit anchor storage | `stkpstagingaudit6117w` + locked container | **MUST-STAY-AZURE** for the external-witness claim — *with a caveat* | See §3.4. `main.tf:823-829` `locked = true`; but `immutability_period_in_days = local.audit_anchor_retention_days` = **1** in staging (`main.tf:20`) | **$1.5/mo** — keep |
| 16 | CI runner VM + NAT + PIP + NSG + NIC + subnet | `vm-kp-staging-runner`, `nat-…`, `pip-…` | **MOVABLE-NOT-YET-MOVED** | VM is `PowerState/deallocated`, but the NAT gateway, public IP and OS disk still bill. All the resources exist, so the last apply carried `deploy_ci_runner=true` (`main.tf:317-405`, `count = local.ci_runner`). Every workflow job is `runs-on: ubuntu-latest` **except** `azure-deploy.yml:340`, which needs `self-hosted,linux,azure-vnet` *only when* `network_mode != 'starter'` | `deploy_ci_runner=false` → **$34/mo**. Only possible together with row 17 |
| 17 | Private networking (5 private endpoints, 5 private DNS zones) | `pep-…` ×5, `privatelink.*` ×5 | **MOVABLE-NOT-YET-MOVED** | `main.tf:858-999`, all `count = local.private_network`. Currently present, so `network_mode = "private"` | `network_mode="starter"` (public + firewall) → **$50/mo**; also unlocks rows 8 and 16. This is a *security-posture* decision, so it wants an operator call, not a silent flip |
| 18 | Container Apps environment | `cae-kp-staging` | **MUST-STAY-FOR-NOW** while any Container App exists | Consumption-only workload profile, `zoneRedundant: false` — no separate idle meter appears in the cost data | $0 standalone |
| 19 | Migration job | `caj-kp-staging-migration` | **ALREADY-LOCAL** equivalent (alembic runs locally) | 09-05 cost $0.001; billed only while executing | $0 |
| 20 | App Insights / Log Analytics / OTel | `appi-kp-staging`, `log-kp-staging` | **ALREADY-LOCAL** for dev | `otel-collector` runs in compose on `.105`. Log Analytics 09-01..09-07 cost **$0.00** (PerGB2018, 30-day retention, 5 GB/day cap) | $0 — leave it; the retention-trim advice in `LOCAL-FIRST-MIGRATION-PLAN.md` Priority 4 targets a cost that does not exist |

**Verdict counts** (rows 1, 2 and 3 carry two verdicts — a local component plus an Azure
remnant — and are counted in both columns, so the totals exceed 20):

- **ALREADY-LOCAL — 8:** rows 1, 2, 3, 4, 5, 10, 19, 20
- **MOVABLE-NOT-YET-MOVED — 8:** rows 1, 3, 6, 7, 8, 14, 16, 17
- **MUST-STAY-AZURE — 3:** rows 9 (ACS), 13 (Microsoft Graph), 15 (WORM anchor)
- **MUST-STAY-FOR-NOW — 4:** rows 2, 11, 12, 18

---

## 3. The four hard questions

### 3.1 Outbound email deliverability — can a local SMTP relay do this?

**Mechanically yes; credibly no, without work that is not merely configuration.**

What is true today:

- The provider seam is real and already selectable. `EmailProviderKind` is `smtp` |
  `azure_communication_services` (`apps/workers/src/kp_workers/config.py:40-61`), selected in
  `providers/smtp.py:415-444`, defaulting to **SMTP** (`config.py:243`). `.105` runs
  `KP_WORKER_EMAIL_PROVIDER=smtp`.
- Open/click tracking is **not** a provider feature — it is a pixel/redirect against the
  platform's own tracking API (`jobs.py:2748-2759`), so it survives any transport change.
- Outbound port 25 is **open** from `.105` (TCP connect succeeded to
  `gmail-smtp-in.l.google.com:25` and `outlook-com.olc.protection.outlook.com:25`; 587 and
  465 also open). Many ISPs block 25; this one does not.

What breaks:

1. **SPF is a hard-fail record that authorises only Microsoft.** The published record at the
   authoritative nameserver is
   `v=spf1 include:spf.protection.outlook.com -all`. A local relay from `.105` is *not* in
   that include, and `-all` means receivers are told to reject rather than soft-fail. Sending
   locally from this domain without editing DNS produces authenticated **failures**, not
   merely lower reputation.
2. **DKIM keys are Azure's.** The two selectors are CNAMEs into
   `selector1/2-azurecomm-prod-net._domainkey.azurecomm.net` — Microsoft holds the private
   keys. A local relay cannot sign as those selectors; it needs its own selector and keypair.
3. **The egress IP is consumer-grade with generic rDNS.** Egress is `47.195.1.166`, PTR
   `47-195-1-166.fdr01.ssds.fl.ip.frontiernet.net` (Verizon/Frontier allocation). Gmail and
   Microsoft bulk-sender rules expect forward-confirmed rDNS aligned to the sending domain.
   Whether Frontier will delegate PTR on this line is **unverified**. A Spamhaus `zen` lookup
   via a public resolver returned empty, which is **not** evidence of being unlisted —
   public resolvers are routinely refused by Spamhaus.
4. **There is no DMARC record at all.** ACS reports `DMARC: NotStarted`, and
   `dig TXT _dmarc.floridamanevolved.us @pdns1.registrar-servers.com` returns nothing. This
   cuts both ways: DMARC is not currently blocking a change, but the "warmed, DMARC-aligned
   sending domain" that the docs imply **does not exist yet**.
5. **A local relay cannot produce delivery receipts** — see §3.3.

**Verdict: MUST-STAY-AZURE**, and the reason is specific: ACS is a *deliverability and
reputation* anchor sitting on Microsoft's shared outbound pool, plus the DKIM signing
authority for this domain. Those are not services you can install; they are standing
relationships with receiving mail systems. That said, the honest boundary is narrower than
"Azure": a third-party relay (SES/Postmark/SendGrid) would serve the same function off Azure.
It would not save money — ACS already costs **$0** at idle — and it would forfeit the Event
Grid receipt path, so there is no reason to do it.

**One nuance worth recording.** For the real product use — simulations sent to a customer's
own employees, whose mail system the customer controls and can allowlist — IP reputation
matters far less than it does for cold bulk mail. If the goal were only "demonstrate an
end-to-end send to a controlled inbox", a local relay plus an SPF/DKIM rewrite would be
achievable in perhaps a day. What it cannot do is send to arbitrary third-party recipients
with confidence. Since ACS costs nothing at idle, that trade is not worth making.

### 3.2 Entra / OIDC — is the "config-only" Keycloak swap real?

`docs/design/INTERNAL-IDP-KEYCLOAK.md` headlines IAM-003 as a "pure configuration change".
**That is partially true and the doc itself qualifies it — but the qualification is the whole
story, and one section of the doc is now factually wrong.**

The verifier's constraints (`apps/operator-api/src/kp_operator_api/auth.py`):

- `http://` is permitted **only** for `localhost`, `127.0.0.1`, `::1` —
  `_LOCAL_OIDC_HTTP_HOSTS` at `auth.py:47`, enforced at `auth.py:169-176`. So
  `http://192.168.1.105:8080/realms/kp` is rejected.
- Over HTTPS, the issuer must resolve to a **globally routable** address —
  `auth.py:229-235` rejects anything failing `_is_global_unicast` (`auth.py:180-190`).
  `192.168.1.105` is not global, so **`https://192.168.1.105/...` is rejected too**, and so
  is a public hostname with a split-horizon record pointing at the LAN, because the check is
  on the *resolved address*.
- The resolved IP is then pinned for the request with Host/SNI preserved
  (`auth.py:240-251`), closing DNS rebinding.
- TLS verification is always on and **there is no hook for a private CA** — `verify=self.ssl_context or True` with `trust_env=False` (`auth.py:306-314`), and `ssl_context`
  is never populated (`auth.py:269`, `auth.py:432-438`). A publicly-trusted certificate is
  effectively required.
- The `allowed_origins` escape valve is HTTPS-only and **no config path populates it** —
  every call site passes nothing (`auth.py:380`, `:393-397`, `:427-431`,
  `console/__init__.py:296-300`, `:363-367`, `console/console_auth.py:148-153`, `:189-194`).
- Validation happens at **process start** (`auth.py:379-382` via `main.py:547-552`), so a bad
  issuer stops the operator-api booting, it does not merely fail a login.
- `apps/operator-api/tests/test_auth.py:82-136` pins all of this with explicit private-range
  cases. Relaxing it means deliberately breaking tests.

**So: real blocker, small-ish fix, but not config.** A self-hosted Keycloak needs a public DNS
name on a public address, a publicly-trusted certificate, and a reverse proxy with
`KC_HOSTNAME` set so discovery echoes the issuer exactly (`auth.py:420-422`). Realistic
effort: **1–2 days** including a tunnel or a small public VPS front-end. The alternative —
relaxing `auth.py:169-176` and `:229-235` behind a new setting — is a deliberate weakening of
an SSRF guard and should not be done to save money.

**Where I disagree with the doc:** §6 of `INTERNAL-IDP-KEYCLOAK.md` asserts that dev-mode is
*not* fail-closed-gated out of a managed posture. That is **no longer true** —
`apps/operator-api/src/kp_operator_api/config.py:247-251` now raises
`"OPERATOR_API_CONFIG_STORE=managed requires OPERATOR_API_OIDC_MODE=oidc; dev-auth is refused
under the managed posture"`. §6 should be struck. Separately, roughly a dozen `console.py:NNN`
citations throughout that doc are unresolvable since ARC-002 split the module into
`console/__init__.py` and `console/console_auth.py`.

**And the larger point the doc does not make.** Swapping the IdP does not remove the Microsoft
dependency, because OIDC login is one of at least four:

1. **Directory sync** — `providers/graph.py` (`graph.microsoft.com`, managed identity, scope
   `.default`), driven by `directory_jobs.py:174-186`; the roster's stable key is
   `DirectoryUser.entra_id`. Mandatory under managed mode (`workers/config.py:409-419`).
2. **Audience groups keyed to Entra group ids** — `routes/audience_groups.py:146,201`.
3. **Reported-phish mailbox** — `providers/microsoft365.py:129-132`, Graph delta query.
4. **Event Grid webhook auth** — `operator-api/config.py:84-95` pins Microsoft's first-party
   Event Grid app id `4962773b-9cdb-44cf-a8bf-237846a00ab7`.

A Keycloak swap covers **only** operator login. The directory and mailbox integrations are the
reason Entra/M365 is load-bearing, and replacing them is a new-provider project.

One asymmetry worth flagging: the worker's provider-URL validator
(`workers/config.py:82-105`) requires HTTPS for non-local hosts but performs **no** DNS
resolution and **no** global-unicast check — so a LAN-hosted "Graph gateway" at
`https://192.168.1.105:8181` would already pass. The strict SSRF hardening is OIDC-specific.
That inconsistency should be resolved by tightening the worker, not by loosening OIDC.

### 3.3 The WORM audit anchor — is the Azure blob still needed?

**Yes, for one specific claim — and the local provider is weaker than the docs imply, and is
not even switched on.**

Two providers exist, both in `apps/workers/src/kp_workers/providers/audit_anchor.py`:
`AzureBlobAuditAnchorProvider` (`:140`, create-only PUT with `If-None-Match: *`) and
`LocalWormAuditAnchorProvider` (`:333`, `O_CREAT|O_EXCL` file write). Selection is
`audit_anchor_jobs.py:174-182` on the `AuditAnchorProviderKind` enum
(`workers/config.py:64-72`), default `AZURE_BLOB` (`config.py:209`).

The local provider's own docstring is the most honest document in the tree
(`audit_anchor.py:333-346`):

> `O_EXCL` prevents *this* code from overwriting an existing anchor, but it does not stop a
> local root user, a compromised worker, or a backup/restore from deleting or rewriting the
> file. … Otherwise treat it as a development / air-gapped-demo convenience, not a
> tamper-proof witness.

Beyond that caveat, three concrete gaps:

- **Nothing in the repo provisions an immutable volume.** The worker creates the directory
  itself (`self._directory.mkdir(parents=True, exist_ok=True)`), and the default path is
  relative to the project root. On `.105` that root is `/dev/sdd`, a plain `ext4` mount —
  same filesystem, same uid as the worker.
- **Wholesale deletion is silently undetected.** `read_recent` returns `[]` if the directory
  is gone (`audit_anchor.py:384`), the read-back loops then iterate nothing, and
  `previous_anchor_hash` resets to `None` (`audit_anchor_jobs.py:146`) — the chain restarts
  with no mismatch raised.
- **The freshness gate reads a Redis heartbeat, not the anchor store, and fails OPEN**
  (`operator-api/main.py:255-283`).

By contrast the Azure guarantee is enforced *outside the host*: `main.tf:823-829` sets
`locked = true` on the container immutability policy, and the custom role's description
(`main.tf:834`) states plainly that "overwrite/delete are blocked by the container's locked
immutability policy, not by omitting write". The account also sets
`shared_access_key_enabled = false` and `default_to_oauth_authentication = true`
(`main.tf:797-809`), so there is no key-based bypass. That is the difference: **a root
compromise of the worker host cannot rewrite published history.**

**The exact claim it backs:** AUD-001's "external anchor / independent immutability"
(`docs/WAVE-BUILD-PLAN.md:529`). Notably, a tree-wide search found **no** SOC 2, ISO 27001,
chain-of-custody, non-repudiation or admissibility claim anywhere — and the claim that does
exist is explicitly recorded as *unproven*: `docs/AI_HANDOFF.md:300` — "independent
immutability remains unqualified until the separate Azure boundary and monitoring/recovery
behavior are proven live".

**Two findings that qualify the Azure side too.** First, in staging the immutability period is
`local.audit_anchor_retention_days`, which is **1 day** for non-production (`main.tf:20`) — so
the current Azure witness guarantees one day of immutability, not a year. Second, Terraform
records `legal_hold = "not_configured_time_based_retention_only"` (`outputs.tf:203`).

**And in practice it is running neither way.** On `.105` the audit-anchor worker is **not
running** (the eight live roles are alert, delivery, directory, generation, ingestion,
mailbox, reminder, retention), no `KP_WORKER_AUDIT_ANCHOR_*` is set in `.env`, and
`data/audit-anchors/` does not exist. This matches
`docs/LOCAL-FIRST-MIGRATION-PLAN.md` ("the Azure Blob audit-anchor worker is not in the local
roster, so it's never invoked") and **contradicts**
`docs/NEXT_SESSION_HANDOFF.md:36-37`, which claims read-back/chain-verified anchors plus local
WORM are live locally. The LOCAL-FIRST description is the accurate one.

Also note `docs/design/AUDIT-CHAIN-INTEGRITY-2026-09.md` is about a *different* AUD-003 — the
audit chain not binding its own columns — and says nothing about anchor providers. The label
`AUD-003` is overloaded in this tree.

**Verdict: MUST-STAY-AZURE at $1.5/mo.** It is the only component here whose value is that it
is *outside* the operator's own trust boundary; reproducing that locally requires hardware or
filesystem-level WORM the repo does not provision. `docs/design/LOCAL-HARDENED-POSTURE.md:67`
lists `s3_object_lock` as a planned third backend; no implementation exists (grep for
`minio|object_lock|boto3` returns zero hits).

### 3.4 Event Grid receipts — the hidden coupling

Worth stating because it constrains rows 9 and 11 together. ACS delivery receipts arrive only
via Event Grid (`acs_receipts.py:310-364`, `WEBHOOK_PATH =
"/api/v1/integrations/acs/events"`). They are the **only** writer of `SendState.DELIVERED`
(`jobs.py:771-786`) and the only source of bounce/spam suppression (`jobs.py:841-856`,
enforced at `jobs.py:1385-1388` and `jobs.py:1893-1897`).

Two things follow. First, a non-ACS receipts backend cannot even be persisted: the schema
carries `CheckConstraint("provider IN ('acs')")` on both
`delivery_provider_events` and `recipient_delivery_suppressions`
(`packages/database/src/kp_database/models.py:867,900`), which
`docs/design/LOCAL-HARDENED-POSTURE.md:85-87` already names as the blocker. So the coupling is
a **code** constraint, not an Azure one.

Second — and this inverts the intuitive reading — the canary launch gate *requires*
`DELIVERED` under ACS but deliberately accepts `ACCEPTED` under SMTP
(`jobs.py:1165-1178`), and that gate blocks full publication
(`routes/campaigns.py:1397-1405`). So SMTP campaigns publish fine; it is **ACS** sends that
cannot be fully published until Event Grid receipts arrive. A broken webhook is a hard stop
for the Azure path and a non-event for the local one.

**Incidental defect found en route, unrelated to cost but worth someone's attention:**
`RecipientDeliverySuppression.active` is set `True` at `jobs.py:848` and `:855` and is
**never set `False` anywhere in the tree**, and no API route or console control lists or
clears suppressions. A recipient who bounces once is permanently excluded from every future
campaign. Whether that is intended is unverified — no design doc states either way.

### 3.5 AI serving — is D-0001 still right?

**Yes, and nothing forces Azure here.**

Qwen2.5-7B-Instruct-Q4_K_M runs locally and was observed serving: `kp-llama` `/health` ok,
`ai-gateway` `/readyz` ready, worker pointed at it via
`KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090`. The seam D-0001 relies on is real — the worker
only calls `POST /propose`, and only the gateway talks to a model backend.

The cost data confirms D-0001's premise empirically. On 09-05 the Azure `ai-gateway` billed
345,256 idle vCPU-seconds and 690,512 idle GiB-seconds — exactly **4 vCPU / 8 GiB held
idle for a full day**, i.e. the ai-llama sidecar spec, for $3.18 that day (~$97/mo) to serve
nothing. By 09-06 it was `ScaledToZero` and cost $0.12. Self-hosting the model in Azure was
demonstrably the wrong shape, and dropping it was correct.

One thing to be honest about: **`AI-015` is not implemented, so there is currently no Azure AI
path at all.** D-0001's Foundry Serverless production path exists on paper only. That is fine
while everything is local, but "production AI" is presently unavailable rather than merely
idle. The decision remains right; the work behind it is outstanding.

---

## 4. Where this audit contradicts existing docs

| Doc | Claim | Finding |
|---|---|---|
| `docs/NIGHTLY-AZURE-SHUTDOWN.md` (What the nightly job stops) | `az containerapp update --min-replicas 0` "Removes the always-on replica charge" | **False for `operator` and `tracking`.** They are `revision_mode = "Multiple"` (`main.tf:1299`, `:1447`); 76 previously-active revisions keep their original `min_replicas = 1`. The script reads the app-level minimum, sees `0`, and skips (`azure-nightly-shutdown.sh:306`). Measured leak: **$29.24/day** |
| `docs/LOCAL-FIRST-MIGRATION-PLAN.md` ("Done today — immediate cost stop") | Scaling to min-0 on 2026-09-05 stopped the cost | **False.** 09-05 was the most expensive day in the window ($44.55) and 09-06 was $35.70 |
| `docs/HYBRID-AZURE-LOCAL-PLAN.md` | "Path B makes idle Azure cost ~$0 today" | **Aspirational, not actual.** Path B's `deploy_data_plane` flag has never been set false (ACR and Redis both still exist), `idle.tfvars` has never been applied (Container Apps still exist), and `network_mode` is still `private` (5 PEs, 5 zones, NAT gateway all present). Measured idle: **~$1,085/mo** |
| `docs/NEXT_SESSION_HANDOFF.md` asset table | "operator / tracking / worker Container Apps — AZURE — IDLED (min-replicas 0)" | True at the app level, misleading in effect. 76 replicas are billing |
| `docs/NEXT_SESSION_HANDOFF.md:36-37` | "read-back/chain-verified anchors + local WORM" live locally | **Not observed.** The audit-anchor worker is not among the 8 running roles, no `KP_WORKER_AUDIT_ANCHOR_*` is set, `data/audit-anchors/` does not exist. `LOCAL-FIRST-MIGRATION-PLAN.md` is right and this line is wrong |
| `docs/NEXT_SESSION_HANDOFF.md` / `HYBRID-AZURE-LOCAL-PLAN.md` | CI runner "deallocated" / `deploy_ci_runner=false` | The **VM** is deallocated, but the NAT gateway, public IP, NSG, NIC and OS disk all still exist and bill ~$34/mo. `deploy_ci_runner` was `true` on the last apply |
| `docs/design/INTERNAL-IDP-KEYCLOAK.md` §6 | Dev-mode is not fail-closed-gated out of a managed posture | **Now false** — `operator-api/config.py:247-251` refuses it. Strike §6. Also ~12 stale `console.py:NNN` citations |
| `docs/LOCAL-FIRST-MIGRATION-PLAN.md` Priority 4 | "Reduce or drop Azure Log Analytics/App Insights retention (idle-time cost)" | There is no idle-time cost. Log Analytics billed **$0.00** every day 09-01..09-07 |

---

## 5. Prioritised: what to move next, what to stop paying for

Ordered by measured saving per unit of effort. **None of this has been executed** — every item
is a proposal requiring an operator decision, and several are Azure writes.

1. **Kill the orphaned revisions — $889/mo, ~2 hours.**
   Deactivate all non-current revisions on `ca-kp-staging-operator` (41) and
   `ca-kp-staging-tracking` (35), then change `revision_mode` to `"Single"` at
   `main.tf:1299` and `main.tf:1447` so it cannot recur. Verify first with
   `az containerapp revision list`; the current revisions are `ca-kp-staging-operator--0000041` and
   `ca-kp-staging-tracking--0000035` respectively (`az containerapp revision list --query "[?properties.trafficWeight==\`100\`].name"`). This is *the* finding of this audit — it is 82% of the bill and it is a bug,
   not a design trade-off. Consider also adding a revision-count assertion to the nightly job
   so a regression is caught rather than paid for.

2. **Apply `idle.tfvars` for real — a further ~$101/mo, ~half a day incl. plan review.**
   `deploy_workloads=false` + `deploy_data_plane=false` destroys the Container Apps ($38/mo
   for the still-running worker), the Premium ACR ($51/mo) and Redis Enterprise ($12/mo).
   The var-file has existed since 2026-09-05 and has never been applied. Note its own warning:
   the GitHub `workloads` phase hardcodes `-var="deploy_workloads=true"`, which outranks a
   var-file, so this must be a direct `terraform apply`. Review the plan and confirm it
   destroys **only** those and shows no Postgres or audit-storage destroy.

3. **Decide on `network_mode="starter"` — ~$84/mo, ~1 day, needs an operator security call.**
   Drops 5 private endpoints ($40/mo), 5 private DNS zones ($10/mo), and — because a
   starter-mode deploy runs on `ubuntu-latest` (`azure-deploy.yml:340`) — the entire CI runner
   chain including the NAT gateway ($34/mo). It also lets ACR drop from Premium to Standard.
   The cost is that the data plane moves to public-endpoint + firewall. This is a genuine
   posture trade-off, not a free win; it should be an explicit decision, ideally recorded as a
   `D-NNNN` entry.

4. **Leave alone, deliberately:** ACS + verified domain + Event Grid + Entra (all **$0**),
   Key Vault ($0.3/mo), audit-anchor storage ($1.5/mo), stopped Postgres ($5.5/mo storage),
   App Insights / Log Analytics ($0.00). Together **under $8/month**. This is the correct
   Tier-1 floor and matches what the existing plans intend.

**Trajectory:** ~$1,085/mo today → ~$196/mo after item 1 → ~$95/mo after item 2 → ~$8/mo after
item 3.

Two non-cost items that came out of the same evidence and want a decision:

- **`AI-015` is unimplemented**, so D-0001's Foundry Serverless production path does not
  exist. Production AI is currently unavailable, not merely idle. Either implement it or
  record explicitly that production AI is deferred.
- **`RecipientDeliverySuppression.active` has no clearing path** (§3.4). A single bounce
  permanently excludes a recipient from all future campaigns. Intentional or not, it should be
  stated somewhere.

---

## 6. Unverified

Stated plainly, because the brief asked for it:

- **Terraform state.** `az storage blob list` on `rg-kp-tfstate-staging` returned
  `Forbidden` (no Storage Blob Data Reader on this principal), so I could not read the state
  file or confirm when Terraform last ran, nor read the last-applied variable values. The
  claim "`deploy_ci_runner` was true on the last apply" is inferred from the CI-runner
  resources existing under `count = local.ci_runner`, not read from state.
- **Key Vault secret inventory.** `az keyvault secret list` returned `ForbiddenByRbac`.
- **Whether Frontier will delegate PTR** for `47.195.1.166`, and the true blocklist status of
  that IP (a public-resolver Spamhaus query returning empty proves nothing).
- **Why the 76 replicas never reach ready.** The observed state is `started=True,
  ready=False, restarts=0`; stopped Postgres and the private data plane are the plausible
  cause, but I did not read container logs (which would have required a write-adjacent
  `az containerapp logs` session against a live app, and the brief said touch nothing).
- **Whether `/root/kingphisher-phoenix` on `.105` matches committed HEAD.** It is not a git
  repository, so it cannot be diffed. Everything asserted about the local stack is about
  *that copy as it is running*, not about HEAD.
- **ACR repository contents.** `az acr repository list` failed with a 403 token refresh
  (admin user disabled, AAD token refused). Only the aggregate 10.13 GB from
  `az acr show-usage` is confirmed.
