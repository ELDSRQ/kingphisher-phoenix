# Deployability & mission-completeness roadmap (2026-09-14)

Derived from a four-part read-only gap analysis of the current tree. Splits the
remaining work into two deployment tracks (local greenfield, Azure greenfield)
and two core-mission tracks (AI aggregation → safe test email; tracked click →
console reporting). Distinguishes **already built** from **genuine remaining
work**, each gap as an actionable task with `file:line` evidence.

**Top-line verdict:** the hardest parts are done — the safe test-email generator
and the click-tracking loop are real and robust, and the feed-based aggregation
works end-to-end. Remaining work concentrates in (1) the **installer entry
points** (both local and Azure break "click-then-only-GUI" at the very start)
and (2) one **mission gap** — the *AI* `/discover` endpoint is an isolated
dead-end, so "AI-aggregated current campaign → safe email" isn't connected.

---

## Track L — Local greenfield (click → fully GUI)

Post-launch GUI is strong: secrets auto-generated (`scripts/bootstrap_env.sh:312-434`),
safe dev defaults, a real onboarding wizard with connection tests + AI assist
(`console/onboarding.py:450-998`), GUI config+restart. The break is at launch.

- **L1 — True greenfield double-click.** The only double-clickable app runs
  `run_console.sh` (relaunch; requires Docker+uv already present); the actual
  installer `scripts/install.sh` is a terminal script that hard-requires
  preinstalled Homebrew (`install.sh:149`) + uv (`install.sh:111-113`). Ship a
  double-clickable/`.command` installer that runs `install.sh` and bundles or
  GUI-prompts for brew+uv.
- **L2 — Docker-context trap.** The active context (`DockerWSL → .105`) makes
  `docker compose up` create infra on `.105` while the app connects to
  `localhost` (`docker-compose.yml:22-23`, `bootstrap_env.sh:334-348`) — a naive
  local install silently targets the wrong daemon. Detect a non-local context and
  force a local engine (Colima/Desktop) or refuse with GUI guidance.
- **L3 — First-run password via GUI.** `KP_CONSOLE_PASSWORD` is auto-generated but
  must be read from `.env` to log in (`install.sh:364-365`, `app.js:929`). Surface
  it in the launcher/first-run screen (or open with a one-time token).
- **L4 — GUI-wrap provisioning + recovery** (error paths are terminal-only:
  `newgrp docker`, `--skip-deps`, re-login — `install.sh:174-185,273`).

## Track Z — Azure greenfield (click → fully GUI)

The wizard's middle is excellent (validate → discover → cost → 3-stage plan →
dispatch → rollback, evidence-gated; `azure_deployment_routes.py`,
`azure-discovery.js`). The ends are manual. Docs concede it
(`docs/AZURE_DEPLOYMENT.md:111`: "not yet 100% GUI-driven").

- **Z1 (biggest) — Move the mutating bootstrap into the GUI.** `scripts/azure_bootstrap.sh`
  (Terraform-state RG/storage, the deployment Entra app + GitHub OIDC federated
  credential, the operator sign-in Entra app + 7 roles, subscription role
  assignments, the 6 GitHub env vars) is entirely CLI (`docs/AZURE_DEPLOYMENT.md:250-308`).
  The wizard only exports values to paste (`app.js:2020-2034`).
- **Z2 — Terraform-configure the dispatch connector** (repository/ref/token) so the
  GUI can dispatch the *first* deploy; today it lights up only after foundation +
  a manual Key-Vault token insert (`deployment_orchestration.py:829-848`,
  `docs/AZURE_DEPLOYMENT.md:108-110`).
- **Z3 — Guided Entra discovery-app registration** so DEP-010 "Discover from Azure"
  works without the manual Entra app/permission/redirect-URI setup (inline hint
  only today, `app.js:2119-2123`).
- **Z4 — ACS DNS in the wizard.** The Azure evidence panel shows only status
  strings, not the DNS record name/type/value/TTL, and verification is by
  re-running a stage (`app.js:1696-1733`). Render the `acs_delivery_readiness`
  records with copy buttons + an in-flow "re-check verification" button. (The
  app's own Domains feature already has such a wizard at `app.js:3791-3927` — a
  template.)
- **Z5 — GitHub env/reviewers/variables via GUI** instead of paste-JSON.
- **Z6 — Guide (don't automate) the inherent human steps:** private `azure-vnet`
  runner bootstrap (`docs:161-177`), M365 admin Graph/Exchange grants
  (`docs:590-643`), operator role assignment to users, operator/tracking FQDN
  DNS+cert binding (`docs:550-560`) — each an in-GUI walkthrough + status.
- **Z7 — Production gate closure** (SAFE-030/AZ-030 live evidence, edge/cert/HSTS/
  backup-restore): production planning is deliberately code-blocked
  (`azure_deployment_routes.py:1001-1005`); greenfield reaches staging only.
- **Z8 (NEW) — Bring-your-own shared enterprise components.** See §Z8 below. Makes
  the platform enterprise-drop-in AND cuts idle cost. Highest cost/value lever.

### Z8 — Bring-your-own shared components (detailed scoping)

**Why:** an enterprise deploying this often already has a Key Vault, WAF/App
Gateway edge, Log Analytics, ACR, and a hardened VNet. Provisioning our own
duplicates them and inflates spend (the private-networking + Premium ACR are the
bulk of even the *idled* cost — see §Cost). WAF/App Gateway are **not built yet**
(`waf_edge: not_implemented`), so they should be designed bring-your-own from the
start (point FQDNs at an existing enterprise edge, don't provision one).

**Pattern (already precedented by ACS):** `acs_resource_mode = provision | existing`
with an `acs_existing_*` ID and a `count`-gated resource + resolver local:
- var + validation: `infrastructure/terraform/variables.tf:413-423`
- local flag: `main.tf:145` (`acs_provision = var.acs_resource_mode == "provision"`)
- gated resource: `main.tf:533` (`count = local.acs_provision ? 1 : 0`)
- resolver: `main.tf:558-559` (`... local.acs_provision ? azurerm_...[0].id : var.acs_existing_...`)

**Apply the same to each shareable component**, most-valuable first:

1. **Key Vault (do first — clearest).** Today always provisioned:
   `azurerm_key_vault.main` (`main.tf:699`), referenced at `main.tf:1120` and by
   the vault private endpoint, secrets, and access policies.
   - Add `key_vault_resource_mode = provision | existing` + `key_vault_existing_id`.
   - `count = local.kv_provision ? 1 : 0` on `azurerm_key_vault.main`.
   - `local.key_vault_id = local.kv_provision ? azurerm_key_vault.main[0].id : var.key_vault_existing_id`;
     replace every `azurerm_key_vault.main.id` with `local.key_vault_id`.
   - In `existing` mode: skip the vault private endpoint + private DNS link
     (assume the enterprise's KV is already reachable), and grant the workload
     identities access to the existing vault (role assignment against the given
     ID) rather than creating access policies on a new vault.
   - Update `test_runtime_contract.py` for the new conditional; add a wizard
     schema field + validation (mirror the ACS existing-ID validation).
2. **ACR** (`acrkpstaging`, Premium) — `container_registry_resource_mode`; in
   `existing`, use the given ACR + its login server, skip the ACR private endpoint.
   (Premium ACR is only needed for our own private link.)
3. **Log Analytics / App Insights** — `observability_resource_mode`; in `existing`,
   send diagnostics to the enterprise workspace.
4. **VNet / subnet + private endpoints** — `network_resource_mode = provision | existing`;
   in `existing`, deploy into the enterprise-supplied subnet, reuse their private
   DNS zones, and skip creating our VNet/NAT/private-DNS.
5. **WAF / App Gateway (net-new, bring-your-own by design)** — do NOT provision.
   Add fields to bind the operator/tracking FQDNs to an existing edge (backend
   pool target + health probe expectations), and document the enterprise-edge
   contract. Fills the `waf_edge` / `default_host_restriction` readiness gaps
   without owning the edge.

Each toggle is independent and lands as its own reviewed PR (Terraform + contract
test + wizard field). Suggest order: KV → ACR → observability → network → edge.

---

## Track M — AI-aggregate current campaigns → safe test email

Safe-email generator is real and robust: allow-list sanitizer strips scripts/
forms/inputs/iframes/img (`safe_html.py:143-190`), triple SafetyValidator rejects
credential/MFA/login + external links (`validator.py:449-489`, enforced at
`jobs.py:557-578`), and the tracked link is per-recipient and bound only at
delivery (`jobs.py:2839-2889`) — no credential capture. The **feed** aggregation
path (RSS/STIX → SourceItem → CampaignPattern → template → send) is complete and
operator-facing. The **AI** path is the gap.

- **M1 (crux) — Bridge `/discover` → the pattern engine.** The AI web_search
  `/discover` endpoint (the literal "AI aggregation of current campaigns",
  `ai-gateway/main.py:530-574`) returns cited leads that are **never persisted** —
  no model, no UI, no path into `CampaignPattern`; only the feed path
  (`SourceItem`) feeds generation. Add a "promote lead → governed `SourceItem`"
  path so the existing activate→pattern→template chain applies.
- **M2 — Build the Threat Discovery UI** (query box, cited results, allowed-domains
  hint, "promote to source/pattern"). Nothing in the console calls
  `/console/discover/search` today.
- **M3 — On-prem AI-aggregation decision.** `/discover` is hard-disabled on-prem
  (no egress → 503, `discovery_routes.py:56-58`) → on-prem "current campaigns" =
  operator-configured feeds only. Decide: document that, ship a seeded default
  feed set, or add a local alternative.
- **M4 — Show "current-specificity" in template review.** Concrete current facts
  reach the generator only via the *optional* P1 `/extract` stage
  (`jobs.py:544-548`); without it the "test email from a current campaign"
  degrades to a generic category theme. Surface extract status / the campaign
  record in the review UI.

## Track T — Tracked click → operator console (sent/clicked by campaign & user)

Largely DONE end-to-end — loop closed, no manual step. Click records a `CLICKED`
event bound to (campaign, recipient) (`tracking-api/routers.py:558-585`); console
shows an aggregate funnel + a capability-gated per-recipient named table
(`routes/campaigns.py:2211-2335`, `app.js:851-966`). Remaining are refinements.

- **T1 — Emit `SEND_ACCEPTED`/`SEND_FAILED` to the immutable event ledger.** They
  are defined (`models.py:171-172`) but never emitted; "sent" lives only on the
  mutable `RecipientAssignment.send_state`, while clicks are append-only events.
- **T2 — Live/near-real-time indication** (the report modal is pull-only; add
  refresh/push if "indicated on the console" means live).
- **T3 — Scale the named per-recipient view** past the 500-recipient browser cap
  (`app.js:857,934-937`): pagination/filter ("clicked-only") + a named per-recipient
  CSV export.
- **T4 — Add an e2e test** for the full send→click→console attribution chain (none
  found).

---

## Cost appendix — idle residual (measured 2026-09-14, rg-kp-staging)

Foundry models (`gpt-oss-120b`/`terra`/`luna`) are all **GlobalStandard** → the
"capacity" is a TPM rate limit, **$0 idle**; no action needed.

Even fully idled, standing infra bills ~$150–190/mo, dominated by the **`private`
network mode + Premium ACR + un-stoppable managed Redis**:

| Resource | ~idle | idle-able? |
|---|---|---|
| 5× Private Endpoints (vault/postgres/redis/acr/audit-anchor) | ~$36/mo | no |
| NAT Gateway + Standard Public IP | ~$36/mo | no |
| Premium ACR | ~$50/mo | no |
| Managed Redis Balanced_B0 | ~$40–60/mo | **no (delete only)** |
| Postgres storage (stopped) + VM OS disk + Log Analytics + storage | ~$20/mo | partial |

**Levers:** (1) test-deploy in `network_mode=starter` (public endpoints, hosted
runner) — removes the ~$120/mo private-networking floor; reserve `private` for
production-like validation. (2) Z8 bring-your-own removes duplicated shared infra.
(3) **Delete-and-rebootstrap** between test sessions → ~$0 standing (tfstate lives
in the separate `rg-kp-tfstate-staging`; Foundry models must be re-deployed
out-of-band on rebootstrap — free, ~minutes).

---

## Suggested sequencing

1. **Cost now:** delete-and-rebootstrap (or starter-mode) to stop paying ~$150/mo
   while building on-prem.
2. **Mission win:** M1 + M2 (connect AI discovery to the pattern engine + its UI).
3. **Enterprise + cost:** Z8 (Key Vault first, then ACR/observability/network/edge).
4. **Local click-to-install:** L1 + L2 + L3.
5. **Azure click-to-install:** Z1 + Z2 + Z4.
6. **Polish:** M4, T1–T4, Z3/Z5/Z6, L4.
7. **Production GO:** Z7 + the live-evidence gates.
