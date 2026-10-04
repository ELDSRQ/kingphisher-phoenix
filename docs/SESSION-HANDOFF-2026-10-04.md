# Session handoff — 2026-10-04 (on-prem feature cycle complete)

**Repo state:** `main` is the deployed state. 0 open PRs, 0 uncommitted work.
`.105` is deployed and running (api healthy, 10 workers including
`worker-curation`). The operator rebooted their Mac workstation (out of memory);
`.105` is a separate host and keeps running — only the Mac SSH tunnel drops.

## Shipped + deployed this cycle (all merged to `main`)
- Branded realistic generation (payload-only safety, no disclaimer)
- Operator logo: file upload + URL; neutralized injection into the draft
- Clone flagging (CLONE pill) + auto-curated flagging (AUTO-CURATED pill)
- BYO-model providers: local / **custom self-hosted** / OpenAI / Gemini /
  Anthropic / OpenRouter / OpenCode (keys encrypted; console selector)
- Forward-a-phish curation: pipeline + ingestion endpoint + dedup (B1), a
  scheduled worker + hardened MIME extractor (B2, fable security-reviewed), the
  Microsoft Graph body-fetch source for Azure (B3), and the library UI
- Generation timeout default 10→60s; runbook docs for the above

CI (hermetic lint/type/tests + Postgres/Redis integration) was green on every PR.

## Re-establish Mac access after reboot
```
ssh -f -N -L 8600:127.0.0.1:8000 -L 8001:127.0.0.1:8001 -L 8025:127.0.0.1:8025 -p 2222 builder@192.168.1.105
```
- Console: http://127.0.0.1:8600/console/  (password `phishingtest2026`, password-only)
- Mailpit: http://127.0.0.1:8025/

## Pending (next session)
1. **BYO model** — operator is adding an OpenRouter key (https://openrouter.ai/keys)
   in Console → Settings → "Generation model & providers". Recommended
   non-refusing model: `nousresearch/hermes-3-llama-3.1-70b`
   (alts: `cognitivecomputations/dolphin-mistral-24b-venice-edition`,
   `nousresearch/hermes-4-405b`). `.105` can reach OpenRouter/OpenCode. The AI
   must not enter the key; the operator pastes it. After selection, trigger a
   generation and confirm the quality improvement over the local model.
2. **D6 human acceptance** (operator's leg): approve a draft → campaign →
   test-cohort send/proof-send → click → training page → evidence export. A full
   self-contained walkthrough was provided. Approved pattern
   `5468dac2`, approved training `00000000-0000-4000-8000-000000000019`.
3. **Curation is live**: forward to `report-phish@corp.example` → auto-curated
   DRAFT within ~60s. Library already has DocuSign/Netflix/Chase (auto) +
   IRS/PayPal/Amazon/BOA/Microsoft/MS365 (manual clones).
4. **Accessibility (D3) re-run deferred** — the console UI changed substantially;
   the a11y Playwright suite needs the full e2e stack, which cannot stand up on
   the thin-client Mac. Run it once Azure staging is up or on a provisioned host.
5. **Azure not started** (gated, billable, interactive `az login`). Operator
   wants on-prem finished + human-tested first as the basis. When greenlit:
   bring staging up, deploy this cycle's work, wire the Foundry 2-model pipeline
   (luna curate + terra build) + the Graph curation source, set the image-host
   allow-list + the generation timeout, verify, re-idle.

## Operational notes
- `.105` `.env` changes this cycle (durable): `KP_WORKER_PROVIDER_TIMEOUT_SECONDS=60`,
  `KP_WORKER_CURATION_MAILBOX_ADDRESS=report-phish@corp.example`,
  `KP_WORKER_CURATION_INTERVAL_SECONDS=60`. Active generation provider = local
  (no BYO key set yet).
- Deploy on `.105` = `git pull` → (`alembic upgrade head` only if a migration
  was added) → `touch data/run/restart`. Gateway prompt/code changes need a
  gateway restart; it is a root-owned systemd unit, restart by killing the
  `builder`-owned process (Restart=always respawns).
- The supervisor now runs as a systemd **user** unit on `.105`
  (`kp-supervisor.service`, see `scripts/operator/onprem-supervisor/`): it
  auto-starts on WSL boot (requires `loginctl enable-linger builder`, done once)
  and auto-restarts the stack if a child crashes. This replaces the old
  hand-relaunched detached process that left the stack down after a reboot.
- Adding a NEW worker role needs the supervisor PROCESS restarted
  (`systemctl --user restart kp-supervisor.service`); `touch data/run/restart`
  only cycles existing children. Code-only worker changes just need the marker.
