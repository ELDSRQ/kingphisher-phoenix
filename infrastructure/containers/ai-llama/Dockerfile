# ai-llama — pinned llama.cpp server with the Qwen2.5-7B-Instruct-Q4_K_M GGUF
# baked in. Runs as the sidecar of the ai-gateway Container App and serves an
# OpenAI-compatible API on loopback :18081 that only the gateway calls.
#
# Built OUT-OF-BAND by the operator with build-ai-llama-image.sh (the CI release
# loop cannot build it: the ~4.7 GB weights are not in the checkout and are
# never auto-downloaded). The base image is supplied pinned-by-digest via the
# LLAMA_BASE build arg; the build script resolves and passes it for you.
#
# The build context must contain the two GGUF shards at ./models/ :
#   models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf
#   models/qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf
# Their sha256 are verified below against the AI-010 selection evidence.

ARG LLAMA_BASE
FROM ${LLAMA_BASE}

# Digest-pinned weights, verified at build. Fail closed on any mismatch.
COPY models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf /models/
COPY models/qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf /models/
RUN set -eu; \
    printf '%s  %s\n' \
      85cb3cc4a0f9533795fd6881c4d5f289c14b24668b4fb2a8fc0ee73832cdf265 /models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf \
      539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a /models/qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf \
      > /models/SHA256SUMS; \
    sha256sum -c /models/SHA256SUMS

# Run as a non-root user (the weights are world-readable and the port is >1024).
USER 65532:65532
EXPOSE 18081
# llama.cpp auto-loads the split GGUF from the 00001-of-00002 shard. Bind to all
# interfaces so the gateway sidecar reaches it over loopback in the shared pod;
# there is no ingress target for this port. Deterministic decoding matches the
# gateway's temperature=0 contract.
ENTRYPOINT ["/app/llama-server"]
CMD ["--model", "/models/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf", \
     "--host", "0.0.0.0", "--port", "18081", \
     "--temp", "0", "--ctx-size", "8192", "--parallel", "1"]
