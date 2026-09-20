# Console Humanization & Deployment Simplification — Implementation Plan

> **For Hermes:** Plan only — no code changes in this turn. Each workstream ships as its own PR (operator merges via `! gh pr merge N --merge`; `ruff check . && ruff format --check .` repo-wide plus the full console suite incl. `test_console_non_azure_wiring_contract`, `test_console_bundle_drift`, `test_ux011_console_wiring_contract` + `npm run build` before any UI PR).

**Goal:** Make Kingphisher-Phoenix simple for a non-technical human security analyst to deploy, configure, and operate — on both the on-prem and Azure paths (both must remain first-class and user-selectable at deploy time) — by replacing machine/AI-readable identifiers with human names, collapsing configuration surface, auto-discovering what the system can learn itself, and humanizing the help/documentation.

**Architecture:** Presentation-first. Safety gates (approval, RoE, canary, allowlist, kill switch) are server-enforced and are NOT touched. All work is usability/visibility: the API already returns enough friendly context (titles, names, display names) in most list views; the work is (a) surfacing that context where the UI currently renders raw IDs/hashes, (b) adding small read-only discovery endpoints/helpers that pre-fill fields, and (c) moving diagnostics behind "Advanced" affordances rather than deleting them.

**Tech Stack:** vanilla-JS console (`apps/operator-ui/src/console-js/*.js`, esbuild bundle committed), FastAPI operator-api (`apps/operator-api/src/kp_operator_api/console/*.py`), Terraform + GitHub Actions (Azure), plain Markdown docs.

---

## Evidence summary (what we measured, with sources)

Four read-only audits (on-prem wizard, Azure wizard, console-UI string catalog, help-docs gaps) produced these headline facts:

1. **The console leaks raw identifiers to humans in ~40 places.** Confirmed worst offenders in `console-js/app.js`: audit "Object" column (`ev.object_id`, :7485), Programs table full `campaign_program_id` UUID (:3742), Program timeline "Campaign ID" (:3686), Executive trends "Campaign reference" full `campaign_id` (:4141), campaign review dialog full `manifest_hash` / `review_manifest_hash` / `bound_content_digest` (:3101–3103), publish dialog full `canary_evidence_hash` (:3504), Sources `source_item_id` / `duplicate_of` (:6501/:6531), terms `terms_hash` 64-hex (:6925), Azure ACS evidence `evidence_digest` + `artifact_sha256` (:1714), dispatch `review_digest` (:1674). Friendly names ALREADY exist in selectors (`recipientReference()`, pattern `lure_category`, template `subject`, lesson `title · version`) — so the naming data is present and reusable.
2. **On-prem wizard has many auto-detectable fields** (`onboarding.py` / `config.py`): OIDC issuer/redirect/audience derivable from one tenant ID + public host; Graph base URL is a fixed constant; STARTTLS/SSL inferable from SMTP port; training/allowed-domains derivable from the training URL host; sending domains derivable from the sender mailbox; the console already auto-tests OIDC/Graph/SMTP/webhook/training reachability but never tells the user what it already checked.
3. **Azure wizard's biggest barrier is the off-GUI prerequisite chain** (Entra app registrations, GitHub protected environment + non-self reviewer, six protected vars, private `azure-vnet` runner, M365 consent, four DNS records) — the GUI neither discovers, auto-fills, nor even lists it as one checklist. Four copy-a-GUID steps (subscription/tenant/client IDs) plus raw `/subscriptions/...` resource URIs and Key Vault secret IDs are all discoverable server-side via `az account show`, `az ad app list --display-name`, tag-based resource discovery, and `az network dns zone list` (the workflow already runs several of these calls to *cross-check* the values it currently asks the human to type).
4. **Help center covers only setup-wizard glossary** (13 terms + 5 topics, `onboarding.py:308–387`); the entire campaign-lifecycle vocabulary a security analyst operates with — RoE, canary, allowlist, approval policy, kill switch vs recall, DNS/SPF/DKIM/DMARC, ACS vs SMTP, Mailpit — is absent. README/RUNBOOK are engineering-grade prose (commit SHAs, migration numbers, test counts, `uv`/Docker/SSH/Terraform/alembic/PID assumptions).

---

## Design principles (pre-loaded from the security critique — see "Critique" section)

1. **Humanize, never hide, safety-relevant evidence.** Anything that is *evidence of a decision* (approval facts, canary success, RoE signature, provider evidence) stays visible — it moves to plain language + a collapsed "Advanced / diagnostics" view, never deleted.
2. **Auto-fill must be read-only and fail-closed.** Discovery endpoints only *suggest*; the reviewed value still binds, and auto-derived defaults never relax the allowlist, approval policy, or domain verification. An unset allowlist still refuses import under OIDC.
3. **Names must disambiguate.** Where two objects can share a friendly name (two campaigns "Q3 Invoice Lure Drill", two patterns in the same lure category), render `Title (8-char-id)` — a short human-usable suffix, not the full 36-char UUID, and never as the primary label.
4. **Do not invent credentials.** Auto-generated passwords are fine; the fix is *first-run human set/reset*, not weakening the secret or logging it.
5. **Both deployment paths stay first-class.** The chooser is about clarity and defaults, never about removing or deprecating one path.

---

## Workstreams

### WS1 — Humanize the console (replace raw IDs/hashes with names)

**Objective:** No raw UUID/hex/digest as a primary label anywhere a human reads. Friendly names become the label; diagnostics collapse behind "Advanced" or a copy/expand control.

**Changes (in `apps/operator-ui/src/console-js/app.js` unless noted):**
- Audit "Object" column (:7485): resolve `object_id` → object title/name where the event payload already carries one; else render `(object_type)` label + truncated id behind an expand control.
- Programs table (:3742) + timeline "Campaign ID" (:3686): use source campaign title + a short disambiguator; add `campaign_title` to the program/timeline API projection if absent (`apps/operator-api/.../program routes`).
- Executive trends "Campaign reference" (:4141): campaign title (join on campaign list already fetched for the view).
- Campaign review/approval/schedule/publish dialogs (:3101–3103, :3411, :3472, :3504): keep `Content digest`, `Campaign manifest`, `Launch review`, `Canary evidence` as **plain-language summary lines** ("Lesson: Verify urgent requests v1", "Canary evidence: provider-accepted (valid 24h)") and move the full 64-hex digests into a collapsed "Diagnostics" block with copy buttons.
- Sources (:6501/:6531/:6925): `source_item_id`/`duplicate_of` → threat title; `terms_hash` → "Terms acknowledged · <date>" with hash behind a copy control.
- Azure deployment (:1674, :1714, :1889, :1838): `review_digest`/`evidence_digest`/`artifact_sha256`/checkpoint `digest` → "verified ✓" badge; raw digests under "Advanced".
- Recipients exclusions (:5443/:5467), privacy (:6077/:6190), directory preview (:5668/:5791/:5823), test-account designation (:5246), recipients aria-labels (:5957), failed-jobs reference (:7375/:7418): use `recipientReference()`/campaign title or collapse to "Advanced".
- Threat aggregation (:7094/:7125): `promoted_pattern_id` → pattern lure category.

**Add a shared UI helper** (e.g. `friendlyId(name, id)` → `name · id.slice(0,8)` or a `<details>` diagnostic) so all ~40 sites use one mechanism. Update the wiring-contract/drift tests that pin these strings.

**Acceptance:** A human can complete the full campaign lifecycle (create→review→canary→publish→report) and the audit view without ever needing to read a 36-char UUID or 64-hex hash as the primary label; every hash remains reachable under "Advanced" for auditors.

### WS2 — Simplify + auto-fill the on-prem setup wizard

**Objective:** First-run is identity + email + training; everything optional is behind "Advanced"; derivable values are pre-filled.

**Changes:**
- Add a read-only **"derive defaults"** step before the wizard (server-side): compute OIDC issuer/redirect/audience from a single Entra tenant ID + the console's public HTTPS address; infer SMTP STARTTLS/SSL from the port; derive `training_domains` from the training-URL host; derive sending domain from the sender mailbox; default Graph base URL to `https://graph.microsoft.com/v1.0`. Present as pre-filled fields the operator confirms, not blank free text.
- Split `_ONBOARDING_STEPS` into **Required** (identity, email delivery, training) and **Advanced integrations** (directory sync, reported mailbox, AI gateway, webhooks). The wizard already gates save on required-only; no routing change beyond grouping.
- **First-run credential UX** (WS4) removes the "read `KP_CONSOLE_PASSWORD` from `.env`" step.
- Add a **"What the console already checks for you"** summary line per step (connection test already covers OIDC discovery, Graph `/users`, SMTP login, webhook TLS, training reachability) so the operator isn't asked to re-verify reachability manually.

**Acceptance:** A first-run on-prem install asks the operator for ≤ 6 free-text values (console password, SMTP host/credentials OR "use Mailpit", sender mailbox, training URL) with everything else pre-filled or advanced-only.

### WS3 — Simplify + auto-discover the Azure deployment wizard

**Objective:** Kill the copy-a-GUID steps and surface the off-GUI prerequisite chain as one tracked checklist.

**Changes:**
- **New read-only discovery endpoint(s)** (operator-api, capability-gated to `administrator`): `az account show` → subscription/tenant; `az ad app list --display-name` → deployment + operator client IDs by friendly name; tag-based discovery of existing Communication/Email services + domains + `hostName`; `az network dns zone list` for same-subscription zones. These return **name + id pairs** so the UI renders name pickers. Structural-only validation posture is preserved — discovery is a separate opt-in read, never folded into save.
- Remove the three `tf_state_*` fields from the human form (preflight already reads them from the protected GitHub env and cross-checks — `github_workflow_gateway.py:514–528`); pre-fill `azure_deployment_client_id` from `AZURE_CLIENT_ID`.
- Pre-fill `ciphertext_active_key_id` from the `ciphertext_keyring` Terraform output post-foundation.
- Surface the exact four ACS DNS records as click-to-copy rows in the GUI (today they only appear in the GitHub step summary / artifact).
- **Prerequisite checklist:** render the residual tenant-admin steps (GitHub env protection, bootstrap, federation, runner, M365 consent, role assignment, DNS) as tracked, linked checkboxes with a friendly readiness summary and per-step "where"/"why".
- Consolidate five pages: keep ~7 org-specific required fields (subscription/tenant, deployment client id, operator + tracking FQDN, sending domain + local part, recipient domains, AI endpoint) top-level; the remaining ~30 become "Advanced" (DEP-010 already has `_AZURE_ADVANCED_KEYS` + `_AZURE_SUGGESTED_DEFAULTS`).

**Acceptance:** A cloud admin can fill the Azure form by *clicking* names (never transcribing a GUID or raw `/subscriptions/...` URI), and can see — in the console — exactly which external prerequisites are still outstanding before dispatch.

### WS4 — First-run credential UX (on-prem)

**Objective:** Remove the "read a random password from `.env`" step without weakening the secret.

**Changes:** On a dev-auth (`oidc_mode == "dev"`) stack with the bootstrap default password still unset-or-default, show a one-time **"Set your console password"** flow (min-length + complexity check, never logged, never in audit, stored via the existing `.env` atomic write path in `env_store.py`). This is a *presentation + one guarded write* change, not a new credential model.

**Acceptance:** First run asks the operator to choose a password; no `.env` grep required; the password is still not printed or logged.

### WS5 — Humanize the help + split docs

**Objective:** Add the missing campaign-lifecycle vocabulary to the Help center; give the operator a plain-language guide while keeping the engineering runbook for engineers.

**Changes:**
- Extend the Help glossary/topics (`onboarding.py:308–387`) with the 12 plain-language definitions already drafted (RoE, canary + evidence, allowlist fail-closed, SMTP vs ACS, SPF/DKIM/DMARC, Mailpit, approval policy 3-way, two-person + self-approval block, kill switch vs recall vs pause, on-prem vs Azure, frozen audience/manifest, provider receipts). Scope the Help view beyond setup (make it navigable from campaign/send screens, not just setup).
- Add a new **`docs/OPERATOR-GUIDE.md`** (plain language, task-oriented: "Deploy on-prem", "Deploy to Azure", "Run your first campaign", "Read the dashboard", "What to do in an emergency") and keep RUNBOOK.md/README.md as the engineering/qualification reference. Cross-link, don't duplicate.
- Fix the broken "See RUNBOOK section 2.1" login hint (app.js:929) to point at the new operator guide.

**Acceptance:** A new non-technical operator can answer "what is a canary / why can't I publish / why is import refused / which emergency control do I use" from in-console help alone.

### WS6 — First-class deployment chooser (the user's explicit requirement)

**Objective:** Make the on-prem vs Azure decision explicit and reversible at deploy time, so a team decides at the moment they deploy — neither path is hidden or deprecated.

**Changes:**
- On first run, present a **"How do you want to run this?"** chooser: "On my own hardware (on-prem)" vs "In Microsoft Azure (managed)" with a plain-language cost/prereq comparison (reuse the bound `deployment_cost.py` estimate for Azure). The choice sets the wizard default, never locks it out.
- Keep both paths fully functional and independently testable (already true); add a settings readout showing which runtime the console is currently attached to (the "Azure managed" pill already exists — extend it with a plain-language explanation).

**Acceptance:** Both paths remain selectable; the console never implies one is legacy.

---

## Non-negotiables (from the critique — must hold in every PR)

- No capability, approval, RoE, canary, allowlist, or kill-switch behavior changes. All server gates untouched.
- Hashes/evidence are **collapsed, not removed** — auditors and the approval workflow can still see them.
- Auto-derived defaults are **suggestions**; the reviewed/bound value still governs; an unset allowlist still fails closed under OIDC.
- Names are **disambiguated** with a short id suffix where titles can collide.
- No credentials are fetched, logged, or weakened; discovery endpoints are read-only and capability-gated.
- Every UI change passes the console-wiring, bundle-drift, and UX-011 contract tests; `npm run build` regenerates the committed bundle.

## Files likely to change

- `apps/operator-ui/src/console-js/app.js` (+ `dom.js`) — WS1/WS4/WS6 UI.
- `apps/operator-api/src/kp_operator_api/console/onboarding.py`, `config.py`, `env_store.py` — WS2/WS4/WS5 help + derive-defaults.
- `apps/operator-api/src/kp_operator_api/console/azure_deployment_routes.py`, `deployment_orchestration.py`, `github_workflow_gateway.py`, new `discovery` route — WS3.
- `apps/operator-api/.../routes/programs.py` (+ any route whose projection needs a friendly title added) — WS1.
- `docs/OPERATOR-GUIDE.md` (new), `README.md` cross-links, `RUNBOOK.md` pointer — WS5.

## Tests / validation

- New: `test_friendly_ids_contract.py` (asserts the shared helper + that no view renders a raw 36-char UUID / 64-hex as a primary label), `test_discovery_endpoints.py` (read-only, capability-gated, name+id pairs), `test_operator_guide_help_contract.py` (12 glossary terms present).
- Existing must stay green: `test_ux011_console_wiring_contract.py`, `test_console_bundle_drift.py`, `test_console_non_azure_wiring_contract.py`, `test_route_authorization_inventory.py` (if routes added), plus `npm run build`.
- Repo-wide `ruff check . && ruff format --check .` before every PR.

## Sequencing (each = one PR)

1. WS1 helper + audit/programs/trends/sources/campaign-dialog humanization (highest-visible wins).
2. WS1 remainder (Azure deployment + recipients + privacy + aggregation) + new friendly-title projections.
3. WS4 first-run credential UX + WS6 deployment chooser (both are small, high-impact).
4. WS2 on-prem derive-defaults + required/advanced split.
5. WS3 Azure discovery endpoints + name pickers + DNS copy + prerequisite checklist.
6. WS5 help glossary expansion + `docs/OPERATOR-GUIDE.md` + cross-links.

## Risks / open questions

- Privacy contract: the pseudonymous ledger drill-down intentionally withholds names (`test_..._never_renders_identity_or_pseudonym`); do NOT "fix" it — it is a privacy requirement, not a usability bug.
- Console no-live-HTML invariant forbids `.srcdoc`/`.innerHTML`; all humanization is text/DOM-node work, no template HTML execution.
- Azure discovery endpoints add an outbound `az` dependency on the operator host — keep them opt-in and non-blocking so structural-only validation is preserved.
