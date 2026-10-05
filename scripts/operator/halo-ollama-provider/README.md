# On-prem generation via a self-hosted Ollama model (HALO)

How the `.105` deployment runs lure generation against an **uncensored local
model on the HALO box** (`192.168.1.24`, an AMD Ryzen AI / Strix Halo system
running Ollama), instead of the weak local aggregate model or a refusing
frontier API. Verified end-to-end 2026-10-04 (`/propose` 200 in ~74 s,
`gemma-3-27b-it-abliterated`).

## Why a model like this
Frontier APIs (OpenAI/Anthropic/Gemini) and OpenAI's open-weight GPT-OSS refuse
to write phishing content even for simulation. An **abliterated/uncensored**
model does not. Good choices present on HALO:
`hf.co/mlabonne/gemma-3-27b-it-abliterated-GGUF:Q4_K_M` (the pick — clean HTML,
no refusal, ~72–85 s on the APU) and `WhiteRabbitNeo-2-70B` (purpose-built for
offensive security, but inconsistent HTML + a >180 s cold-load).

## The three pieces

### 1. Reach HALO's Ollama (`kp-halo-tunnel.service`)
Ollama listens on `192.168.1.24:11434`, but HALO's nftables firewall (managed by
the separate CROW workstream) exposes only SSH. Rather than touch that firewall,
`.105` runs a boot-persistent forward tunnel over the open `:22`:

```
install -m 0644 kp-halo-tunnel.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now kp-halo-tunnel.service
```

Requires linger on `builder` (already set) and a **scoped** key in
`edierks@192.168.1.24:~/.ssh/authorized_keys`:
`restrict,port-forwarding,permitopen="192.168.1.24:11434" ssh-ed25519 <builder@.105 key>`
— it can only forward to Ollama; no shell, no other forwards.

### 2. Gateway: structured-output + temperature (`gateway-override.conf`)
The gateway needs two env changes for any llama.cpp/Ollama backend (see that
file for the why). Install the root drop-in (on `.105`, via `wsl -u root`):

```
cp gateway-override.conf /etc/systemd/system/kp-ai-gateway.service.d/override.conf
systemctl daemon-reload && systemctl restart kp-ai-gateway
```

### 3. Select the provider
Point the BYO **Custom** provider at the tunnel and activate it — via the
console (Settings → "Generation model & providers" → Custom) or equivalently:
- `ai_generation_providers` row `custom`: `base_url=http://127.0.0.1:11434/v1`,
  `model_id=hf.co/mlabonne/gemma-3-27b-it-abliterated-GGUF:Q4_K_M`,
  `is_active=true` (others false);
- write `data/run/ai-provider.json`
  (`{"provider":"custom","base_url":"http://127.0.0.1:11434/v1","model_id":"…","api_key":"","auth_style":"none"}`, 0600);
- pin `KP_WORKER_AI_MODEL_ID` to the same tag in `.env`, then
  `touch data/run/restart`.

No data leaves the LAN: generation evidence + the lure go `.105` → tunnel →
HALO only.

## Verify
```
curl -s http://127.0.0.1:11434/v1/models        # tunnel up on .105
# /propose smoke test (expects HTTP 200, model_id = the gemma tag):
```
Generation runs in a background worker, so the ~72–85 s APU latency is not
user-blocking. The incoming `.186` RTX 3090 would run the same model ~3–5×
faster; repoint the Custom provider's base_url at it when ready — no code change.
