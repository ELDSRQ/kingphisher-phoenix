# On-prem generation via Alice's model

Points the `.105` generation worker at the Qwen3-30B-A3B model already loaded on
Alice (`192.168.1.36`), instead of the bundled `mock-ai`. Set up and verified
2026-09-26.

## Topology (everything but the model runs on `.105`)

```
.105 worker ──/propose──▶ ai-gateway (127.0.0.1:8090)
                              │  proxies OpenAI /v1/chat/completions
                              ▼
                    tunnel 127.0.0.1:18081  ──SSH──▶  Alice 127.0.0.1:18082
                                                        (llama-server, shared)
```

- **The model on Alice is never touched.** No process, unit, port, model, or
  config change on Alice. We only add a *consumer*. The llama-server runs with
  4 slots, so generation shares alongside Scribe (`.216`) and the aggregation
  feature rather than blocking them. See [[alice-rtx-aggregation-model-host]].
- The gateway returns its configured `model_id` (`qwen3-30b-a3b-aggregate`), and
  the worker pins the same value, so the model-identity gate matches. See
  [[generation-model-pin-must-match-backend]].

## One-time prerequisite (on Alice, elevated — operator action)

`.105`'s forward-only key must be authorized on Alice. This is a persistence
action on another host, so an operator runs it, not the agent:

```powershell
Add-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value 'restrict,port-forwarding,permitopen="127.0.0.1:18082" ssh-ed25519 <PUBKEY> kp-105-to-alice-llama-tunnel' -Encoding ascii
```

The key is deliberately `restrict,port-forwarding,permitopen="127.0.0.1:18082"`
— it can ONLY forward to the model port, never open a shell or reach anything
else on Alice. The private key lives at `/home/builder/.ssh/alice_llama_tunnel_ed25519`
on `.105`.

## Install on `.105` (inside WSL, as root)

```bash
install -m0644 kp-alice-llama-tunnel.service kp-ai-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now kp-alice-llama-tunnel.service kp-ai-gateway.service
```

Then set in `.105`'s `.env` and restart the stack (`touch data/run/restart`):

```
KP_WORKER_AI_BASE_URL=http://127.0.0.1:8090
KP_WORKER_AI_MODEL_ID=qwen3-30b-a3b-aggregate
```

## Verify

```bash
systemctl is-active kp-alice-llama-tunnel kp-ai-gateway     # active active
curl -s http://127.0.0.1:18081/v1/models | grep qwen3       # tunnel -> Alice
curl -s http://127.0.0.1:8090/... (via a /propose)          # gateway 200
```
End to end: approve a pattern in the console; the draft's `model_id` should be
`qwen3-30b-a3b-aggregate`, and Alice's `/root/kp-aggregate-server.log` should
show a fresh completion on one slot.

## Revert to the bundled mock

Set `KP_WORKER_AI_BASE_URL=` (empty) and `KP_WORKER_AI_MODEL_ID=mock-ai/0.2.0`
in `.env`, restart the stack, and `systemctl disable --now kp-ai-gateway
kp-alice-llama-tunnel`. Nothing on Alice needs undoing.
