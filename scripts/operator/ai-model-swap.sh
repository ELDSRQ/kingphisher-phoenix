#!/usr/bin/env bash
# kp-ai-swap.sh — swap the RTX 3090 between the two resident AI models on Alice.
#
# Alice (192.168.1.36) has a single 24 GB GPU shared by two models that cannot
# fit at once:
#   * qwen3-30b-a3b-aggregate (llama.cpp, port 18082, ~19 GB) — THIS build's
#     generation + aggregation model (Qwen3-30B-A3B-Instruct-2507, MoE). Served
#     by a bare llama-server process (root-owned, auto-started at Windows/WSL
#     boot, not systemd-managed).
#   * qwen3:32b              (Ollama, port 11434, ~20 GB)     — the operator's
#     model for a separate system. Ollama is systemd-managed (Restart=always)
#     and loads/unloads the model from VRAM on demand.
#
# Because ~19 GB + ~20 GB > 24 GB, exactly one of the two may be resident at a
# time. This script makes the switch safe and reversible while preserving the
# aggregation model's identity pin (the ai-gateway fails closed if the served
# model does NOT self-report `qwen3-30b-a3b-aggregate`, so the restart below pins
# the exact alias and flags the boot path uses).
#
# Install (run once, on Alice inside WSL Ubuntu-24.04):
#   sudo install -m 755 /path/to/this/file /opt/kp-ai010/kp-ai-swap.sh
#
# Usage (run on Alice inside WSL):
#   sudo /opt/kp-ai010/kp-ai-swap.sh qwen        # stop aggregation, free GPU for qwen3:32b
#   sudo /opt/kp-ai010/kp-ai-swap.sh aggregate   # stop qwen3:32b, restore aggregation model
set -euo pipefail

AGG_MODEL="/opt/kp-ai010/qwen3-30b-a3b/Qwen3-30B-A3B-Instruct-2507-Q4_K_M.gguf"
LLAMA_BIN="/opt/kp-ai010/llama.cpp/build-cuda/bin/llama-server"
LLAMA_PORT=18082
LLAMA_ALIAS="qwen3-30b-a3b-aggregate"
LLAMA_LOG="/var/log/kp-ai010-llama-swap.log"
QWEN_MODEL="qwen3:32b"

llama_running() { pgrep -f "llama-server.*${AGG_MODEL}" >/dev/null 2>&1; }

log() { printf '%s\n' "$*"; }

swap_to_qwen() {
  log "Stopping aggregation model (${LLAMA_ALIAS}) to free ~19 GB VRAM..."
  if llama_running; then
    pkill -TERM -f "llama-server.*${AGG_MODEL}" 2>/dev/null || true
    local _
    for _ in $(seq 1 30); do
      llama_running || break
      sleep 1
    done
    if llama_running; then
      log "  graceful shutdown timed out; forcing kill"
      pkill -KILL -f "llama-server.*${AGG_MODEL}" 2>/dev/null || true
    fi
  else
    log "  already stopped"
  fi
  log "Done. qwen3:32b is ready via Ollama (http://127.0.0.1:11434)."
  log "It loads on first request and unloads after idle (OLLAMA_KEEP_ALIVE, default 5m)."
}

swap_to_aggregate() {
  log "Unloading ${QWEN_MODEL} from VRAM..."
  if ollama stop "$QWEN_MODEL" >/dev/null 2>&1; then
    log "  unloaded"
  else
    log "  not loaded (nothing to unload)"
  fi
  if llama_running; then
    log "Aggregation model already running; nothing to do."
    return 0
  fi
  log "Starting aggregation model (${LLAMA_ALIAS}) on :${LLAMA_PORT}..."
  nohup "$LLAMA_BIN" -m "$AGG_MODEL" \
    --host 0.0.0.0 --port "$LLAMA_PORT" \
    --ctx-size 32768 -fa on -ctk q8_0 -ctv q8_0 -ngl 99 --threads 16 --jinja \
    --alias "$LLAMA_ALIAS" >>"$LLAMA_LOG" 2>&1 </dev/null &
  local _
  for _ in $(seq 1 90); do
    curl -sf "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 && break
    sleep 2
  done
  if curl -sf "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1; then
    log "  healthy: $(curl -sf "http://127.0.0.1:${LLAMA_PORT}/health")"
  else
    log "  WARNING: not healthy after 180s; see ${LLAMA_LOG}"
    return 1
  fi
}

case "${1:-}" in
  qwen|other) swap_to_qwen ;;
  aggregate|agg) swap_to_aggregate ;;
  *)
    log "usage: $0 {qwen|aggregate}" >&2
    log "  qwen       stop aggregation model, free GPU for qwen3:32b (Ollama)" >&2
    log "  aggregate  stop qwen3:32b, restore aggregation model (Qwen3-30B-A3B)" >&2
    exit 2
    ;;
esac
