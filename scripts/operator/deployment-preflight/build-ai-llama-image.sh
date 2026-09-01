#!/usr/bin/env bash
# Build and push the ai-llama sidecar image (pinned llama.cpp + the
# digest-verified Qwen2.5-7B-Instruct-Q4_K_M GGUF) to the deployment ACR, then
# print the exact AI_LLAMA_IMAGE value to pin.
#
# Run this on a host that holds the digest-pinned weights and can reach the ACR
# (e.g. the .140 worker, where the bake-off shards live under
# /Volumes/DockerExternal/KingPhisher-Phoenix/ai010-models/qwen2.5-7b-instruct/).
# The CI release loop deliberately cannot build this image: the ~4.7 GB weights
# are not in the repo and are never auto-downloaded.
#
# Prerequisites (all operator-supplied, nothing fetched here):
#   1. Pin the llama.cpp base digest in infrastructure/containers/ai-llama/Dockerfile
#      (replace REPLACE_WITH_PINNED_LLAMA_CPP_SERVER_DIGEST).
#   2. Place the two GGUF shards in the build context at ./models/ (see the
#      Dockerfile header for the exact filenames and sha256).
#   3. az login to the deployment subscription; know the ACR name.
#
# Usage:
#   ACR=<acr-name> ./scripts/operator/deployment-preflight/build-ai-llama-image.sh
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

: "${ACR:?set ACR=<acr-name> (the deployment container registry, e.g. acr-kp-staging-xxxx)}"
CONTEXT_DIR="infrastructure/containers/ai-llama"
TAG="ai-llama:$(git rev-parse --short HEAD)"

for shard in \
  models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf \
  models/qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf; do
  [ -f "$CONTEXT_DIR/$shard" ] || { echo "error: missing weight shard $CONTEXT_DIR/$shard" >&2; exit 1; }
done
if grep -q REPLACE_WITH_PINNED_LLAMA_CPP_SERVER_DIGEST "$CONTEXT_DIR/Dockerfile"; then
  echo "error: pin the llama.cpp base digest in $CONTEXT_DIR/Dockerfile first" >&2
  exit 1
fi

echo "building $TAG in ACR $ACR (context uploads the ~4.7 GB weights; this is slow)"
az acr build \
  --registry "$ACR" \
  --image "$TAG" \
  --file "$CONTEXT_DIR/Dockerfile" \
  --platform linux/amd64 \
  "$CONTEXT_DIR"

login_server="$(az acr show --name "$ACR" --query loginServer --output tsv)"
digest="$(az acr repository show --name "$ACR" --image "$TAG" --query digest --output tsv)"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "error: ACR returned an invalid digest: $digest" >&2; exit 1; }

echo
echo "ai-llama image built and pushed. Pin this immutable reference:"
echo "  ${login_server}/ai-llama@${digest}"
echo
echo "Then set it as the staging environment repo variable AI_LLAMA_IMAGE and"
echo "set DEPLOY_AI_GATEWAY=true, so the workloads deploy provisions the gateway:"
echo "  gh variable set AI_LLAMA_IMAGE  --env staging --body '${login_server}/ai-llama@${digest}'"
echo "  gh variable set DEPLOY_AI_GATEWAY --env staging --body 'true'"
