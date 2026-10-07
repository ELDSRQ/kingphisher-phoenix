# Session handoff — 2026-10-06 (QA remediation complete; on-prem human-ready)

Supersedes `docs/SESSION-HANDOFF-2026-10-04.md`.

**Repo state:** `main` is the deployed state, **0 open PRs**, **0 uncommitted**
(this handoff + `docs/QA-REVIEW-2026-10-05.md` land in the same PR). `.105` is
deployed to the same `main` and running (api/tracking/gateway healthy, 10
workers incl. `worker-curation`). The supervisor and the HALO tunnel are
boot-persistent systemd `--user` units (linger on), so a `.105` reboot brings
the stack back by itself; only the operator's Mac SSH tunnel drops.

---

## What this cycle did: remediated `docs/QA-REVIEW-2026-10-05.md`

An independent adversarial QA review was delivered and remediated **impact-first,
minimal, no overengineering** (operator's explicit steer: impact before security,
address security lightly, do not overengineer). Eight PRs, each small + tested,
CI green, all merged:

| PR | Finding | Change |
|---|---|---|
| #122 | broken self-hosted generation + **R-05** | Gateway `response_format_mode` default is now `auto` — resolves per backend (`entra`→`json_schema`, self-hosted `none`→`json_object`), so a fresh self-hosted install generates without hand-tuning (llama.cpp/Ollama cannot compile the json_schema grammar and 400s). A selected-but-unusable BYO provider now returns a stable **503 `provider_state_unavailable`** instead of silently falling back to local. |
| #123 | **R-02** | Egress is classified from the *actual* base URL (`classify_egress`/`provider_egress`: loopback/RFC1918/`.local` = on_network, else offsite) and recorded in the audit chain + provider list — not the static preset flag that could stamp "no data leaves your network" into the immutable audit for a public endpoint. |
| #124 | **R-06**, **R-04** (doc) | README "Current state (as of 2026-10-05)" note (head `0042`, **ten** worker roles incl. curation, ~3,500 tests, profiles re-run pending); honest key-at-rest wording (DB encrypted, but the active hosted provider's key is also plaintext in `data/run/ai-provider.json` — treat `data/` as secret). |
| #125 | **R-01** (a) | `tests/test_azure_idle_contract.py::test_start_initialises_the_backend_too` now fails self-diagnosing (prints rc/stdout/stderr/calls) instead of a bare `IndexError`. |
| #126 | **R-03** | Extracted `packages/curation` (`kp_curation`: `clone_service` + `curation_service`) and moved `KPProfile` to `kp_domain_models.profile`. The worker **no longer depends on `kp-operator-api`**; a boundary test (`apps/workers/tests/test_package_boundary.py`) fails closed if that import returns. |
| #127 | **R-08** | Supervised worker: `KP_WORKER_SUPERVISE_SHARED_DB=1` opt-in (default off) shares one `KP_WORKER_DATABASE_URL` across roles; the missing-var error now names the variable, role, and fallback. |
| #128 | **R-11** | Curation mailpit/Graph fetch failures now log a **warning** naming the cause (were silently swallowed). |

### Deliberately NOT changed (these are correct calls, not gaps)
- **R-07 (aggregation staleness)** — **already implemented** before the QA (banner
  added in `db62a9d`, present at the QA's own commit; candidates show "As of:",
  trends show "Generated…"). The QA missed it. No change.
- **R-10 (UUID fragments)** — cosmetic (LOW), and the prescribed fix ("route every
  site through `recipientLabel`") is wrong: the `slice(0,8)` sites are a mix of
  recipient/campaign/privacy/source IDs and most already carry a human label.
  `recipientLabel` resolves recipients only. Left as-is.

### Deferred with reasons (tracked, not built)
- **R-01 root cause** — eliminating the flake needs reproducing the `azure-idle.sh`
  early-exit under host load; #125 makes it diagnosable, the removal is pending.
- **R-04 code** (encrypt the on-disk key) — only bites when a *hosted* provider is
  active (rare on-prem; frontier refuses phishing); the fix means giving the
  gateway the KEK (expands its blast radius) or a key-fetch endpoint. Doc fixed;
  code deferred per the no-overengineering steer.
- **UX Wave 2** (two-button launch, checklist landing, stop consolidation) — a
  deliberate UX pass better tied to the D3/D6 human gates.

---

## Generation: HALO self-hosted Ollama (the key operational detail)

On-prem lure generation runs against an **uncensored local model on the HALO box**
(`192.168.1.24`, Ollama), not the weak aggregate model or a refusing frontier API.
Active provider = **`custom`** → `hf.co/mlabonne/gemma-3-27b-it-abliterated-GGUF:Q4_K_M`.
Verified end-to-end post-deploy: `/propose` → ~76 s → complete branded lure,
neutralized training link. Three pieces (full runbook: `scripts/operator/halo-ollama-provider/README.md`):

1. **Tunnel** — `kp-halo-tunnel.service` (systemd `--user` on `.105`) forwards
   `127.0.0.1:11434` → `192.168.1.24:11434` over SSH (HALO's CROW-managed nftables
   exposes only :22), using a `restrict,port-forwarding,permitopen=` scoped key in
   `edierks@192.168.1.24:~/.ssh/authorized_keys`.
2. **Gateway** — root drop-in `/etc/systemd/system/kp-ai-gateway.service.d/override.conf`
   sets `KP_AI_GATEWAY_RESPONSE_FORMAT_MODE=json_object` + `KP_AI_GATEWAY_SEND_TEMPERATURE=false`
   (edit via `wsl -u root`, no password; then `systemctl daemon-reload && systemctl restart kp-ai-gateway`).
   With #122's `auto` default the explicit `json_object` is now redundant but harmless;
   `send_temperature=false` is still required (temperature=0 makes abliterated models run away).
3. **Provider row** — `ai_generation_providers.custom` active (base_url
   `http://127.0.0.1:11434/v1`, the gemma tag) + state file `data/run/ai-provider.json`.

HALO model options (all uncensored, won't refuse): gemma-27b-abliterated (the pick —
clean HTML, ~75 s), `huihui_ai/deepseek-r1-abliterated:70b`, `WhiteRabbitNeo-2-70B`
(security-purpose-built but inconsistent HTML + 184 s cold-load). The incoming
`.186` RTX 3090 would run the same model ~3–5× faster — repoint the Custom provider's
base_url at it when ready (no code change). See `ai-generation-host-options` memory.

---

## Deploy mechanics for `.105` (updated)

`ssh -p 2222 builder@192.168.1.105` → `cd ~/phishing-awareness-platform`.

- Normal code deploy: `git pull --ff-only origin main` → (`.venv/bin/alembic -c
  packages/database/alembic.ini upgrade head` **only if a migration was added**) →
  `touch data/run/restart`.
- **A PR that adds/changes a workspace package or dependency (like R-03 did) needs
  `UV_PYTHON_DOWNLOADS=never uv sync --frozen --all-packages` on `.105`** — the
  supervisor runs `uv run --frozen --no-sync`, so a new package (`kp_curation`) is
  NOT installed by the restart marker alone. Symptom if skipped: `ModuleNotFoundError`.
- New worker role or app/worker code change → `systemctl --user restart kp-supervisor.service`.
- Gateway code/prompt/env change → restart the gateway: `kill $(systemctl show
  kp-ai-gateway -p MainPID --value)` (process is `builder`-owned, `Restart=always`
  respawns with fresh editable code).
- Current migration head: **`0042_campaign_created_at`** (no new migration this cycle).
- CI: branch protection requires branches up-to-date, so merges serialize — merge
  one, `gh pr update-branch N` the rest, let CI re-run, merge. Use `--merge` (bare
  `--auto` silently fails).

---

## Pending (next session / operator)

1. **Operator D6 human validation** (the gating item for on-prem sign-off). A full
   self-contained runbook was given; essentials: console `http://127.0.0.1:8600/console/`
   (password retrieved privately from the deployed `.env`), Mailpit `http://127.0.0.1:8025/`. Ready material:
   approved templates `e8a4ce71` (M365), `fafa4682` (IRS), `7c6bc9cd` (Invoice);
   approved lessons `00000000`, `ee756363`; campaign `639ff281` awaiting approval;
   12 DRAFT library templates. Flow: approve/choose a template → campaign → freeze
   audience → canary send → open in Mailpit → click → training page → publish →
   evidence export, driven unassisted with nothing fixed mid-run.
2. **Accessibility (D3)** — deferred; needs a provisioned host/Azure staging, not the
   thin-client Mac. Run when staging is up.
3. **Azure** — still **GATED** (billable, interactive `az login`; operator wants
   on-prem human-tested first). When greenlit, deploy this cycle's `main` (migration
   `0042` lands via the operator container; **the gateway needs the self-hosted
   env only if Azure points at a llama.cpp/Ollama backend — with Foundry/`entra`
   the new `auto` default correctly selects `json_schema`, so leave the Azure gateway
   unset**), wire Foundry + Graph curation source, verify, re-idle.
4. **Deferred QA follow-ups:** R-01 root cause, R-04 key-file encryption, UX Wave 2.

## Re-establish operator access after a Mac reboot
```
ssh -f -N -L 8600:127.0.0.1:8000 -L 8001:127.0.0.1:8001 -L 8025:127.0.0.1:8025 -p 2222 builder@192.168.1.105
```

## Hard rules carried forward
- `.140` is retired — never used for anything. Docker/engine work is `.105` only;
  the Mac has no daemon and never hosts model weights.
- Never touch another AI session's branches/PRs/files, even in this repo; no mass
  remote-branch prune (there are many stale `origin/docs/*` branches — leave them).
- Never auto-kill operator agent shells; process guardrails warn + human-in-the-loop.
