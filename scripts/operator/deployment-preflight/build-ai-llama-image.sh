#!/usr/bin/env bash
# Turnkey build+push of the ai-llama sidecar image (pinned llama.cpp + the
# digest-verified Qwen2.5-7B-Instruct-Q4_K_M GGUF), then print the exact
# gh variable commands to enable the gateway in the workloads deploy.
#
# Run this on the .140 worker (it has Docker and the digest-pinned weights).
# The CI release loop deliberately cannot build this image: the ~4.7 GB weights
# are not in the repo and are never auto-downloaded.
#
# Inputs (env vars; defaults target the .140 layout):
#   ACR        (required) deployment container registry name, e.g. acr-kp-staging-6117w
#   MODEL_DIR  directory holding the two GGUF shards
#              (default: /Volumes/DockerExternal/KingPhisher-Phoenix/ai010-models/qwen2.5-7b-instruct)
#   LLAMA_REF  llama.cpp server image to pin (default: ghcr.io/ggml-org/llama.cpp:server)
#   LLAMA_BASE fully pinned base ref (default: resolved from LLAMA_REF's digest)
#
# Before running: authenticate once with `az login` (interactive) to the
# deployment subscription. az login cannot run headless, so do it yourself.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

: "${ACR:?set ACR=<registry-name>, e.g. ACR=acr-kp-staging-6117w}"
MODEL_DIR="${MODEL_DIR:-/Volumes/DockerExternal/KingPhisher-Phoenix/ai010-models/qwen2.5-7b-instruct}"
LLAMA_REF="${LLAMA_REF:-ghcr.io/ggml-org/llama.cpp:server}"
CONTEXT_DIR="infrastructure/containers/ai-llama"
SHARD1="qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf"
SHARD2="qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf"

# 1. Stage the weights into the build context (git-ignored; copied, not committed).
mkdir -p "$CONTEXT_DIR/models"
for shard in "$SHARD1" "$SHARD2"; do
  if [ ! -f "$MODEL_DIR/$shard" ]; then
    echo "error: weight shard not found: $MODEL_DIR/$shard" >&2
    echo "       set MODEL_DIR to the directory holding the two GGUF shards." >&2
    exit 1
  fi
  cp -f "$MODEL_DIR/$shard" "$CONTEXT_DIR/models/$shard"
done

# 2. Resolve the llama.cpp base image to an immutable digest to pin.
if [ -z "${LLAMA_BASE:-}" ]; then
  echo "resolving pinned digest for $LLAMA_REF ..."
  base_digest="$(docker buildx imagetools inspect "$LLAMA_REF" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
  if [ -z "$base_digest" ]; then
    docker pull "$LLAMA_REF" >/dev/null
    base_digest="$(docker inspect --format '{{index .RepoDigests 0}}' "$LLAMA_REF" | sed 's/.*@//')"
  fi
  [[ "$base_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "error: could not resolve a digest for $LLAMA_REF; set LLAMA_BASE=<ref@sha256:...> explicitly" >&2; exit 1; }
  LLAMA_BASE="${LLAMA_REF%%:*}@${base_digest}"
fi
echo "pinned base: $LLAMA_BASE"

# 3. Build in ACR (uploads the ~4.7 GB context; slow). No local daemon needed.
TAG="ai-llama:$(git rev-parse --short HEAD)"
echo "building $ACR/$TAG ..."
az acr build \
  --registry "$ACR" \
  --image "$TAG" \
  --file "$CONTEXT_DIR/Dockerfile" \
  --build-arg "LLAMA_BASE=$LLAMA_BASE" \
  --platform linux/amd64 \
  "$CONTEXT_DIR"

login_server="$(az acr show --name "$ACR" --query loginServer --output tsv)"
digest="$(az acr repository show --name "$ACR" --image "$TAG" --query digest --output tsv)"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "error: ACR returned an invalid digest: $digest" >&2; exit 1; }
image_ref="${login_server}/ai-llama@${digest}"

echo
echo "=================================================================="
echo "ai-llama image built and pushed:"
echo "  $image_ref"
echo
echo "Now enable the gateway for the workloads deploy (copy/paste both):"
echo "  gh variable set AI_LLAMA_IMAGE --env staging --repo ELDSRQ/kingphisher-phoenix --body '$image_ref'"
echo "  gh variable set DEPLOY_AI_GATEWAY --env staging --repo ELDSRQ/kingphisher-phoenix --body 'true'"
echo "=================================================================="
