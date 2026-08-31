#!/usr/bin/env bash
# Run the internal AI generation gateway (kp-ai-gateway) against a pinned
# llama.cpp model. This is the supported AI-010 inference path.
#
#   ./scripts/operator/ai-gateway/run-gateway.sh [LLAMA_BASE_URL] [PORT]
#
# Defaults: LLAMA_BASE_URL=http://127.0.0.1:18081/v1  PORT=18090
# The model identity is pinned to the AI-010 selection and returned verbatim on
# every proposal; do not change it without re-running the bake-off.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

LLAMA_BASE_URL="${1:-http://127.0.0.1:18081/v1}"
PORT="${2:-18090}"
MODEL_ID="llama.cpp/Qwen2.5-7B-Instruct-Q4_K_M"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 2; }
echo "checking the pinned llama.cpp server at ${LLAMA_BASE_URL%/v1}/health"
if ! curl -sf --max-time 5 "${LLAMA_BASE_URL%/v1}/health" >/dev/null 2>&1; then
  echo "error: llama.cpp is not reachable at $LLAMA_BASE_URL" >&2
  echo "  start it first: llama-server -m <qwen2.5-7b Q4_K_M gguf> --host 127.0.0.1 --port 18081" >&2
  exit 1
fi

echo "starting kp-ai-gateway on 127.0.0.1:$PORT -> $LLAMA_BASE_URL (model $MODEL_ID)"
exec env \
  KP_AI_GATEWAY_LLAMA_BASE_URL="$LLAMA_BASE_URL" \
  KP_AI_GATEWAY_MODEL_ID="$MODEL_ID" \
  KP_AI_GATEWAY_HOST=127.0.0.1 \
  KP_AI_GATEWAY_PORT="$PORT" \
  KP_AI_GATEWAY_REQUEST_TIMEOUT_SECONDS=180 \
  .venv/bin/python -m kp_ai_gateway
