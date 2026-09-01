# Building and deploying the ai-llama sidecar (Qwen in Azure)

This is **optional** and only needed to run Qwen inside Azure (the `workloads`
phase). Qwen already works locally via `docker compose --profile ai up
ai-gateway`. Nothing is broken without it.

The image bakes the digest-pinned `Qwen2.5-7B-Instruct-Q4_K_M` GGUF into a
pinned `llama.cpp` server, verifying the weights' sha256 at build. It is built
out-of-band (the CI release loop can't bundle the ~4.7 GB never-auto-downloaded
weights).

## Recommended path: build via GitHub OIDC (no laptop `az`)

The tenant's Entra **security defaults** block interactive Azure CLI login from
a laptop, so build through the OIDC identity the deploy already uses — the same
mechanism that ran bootstrap/finalize. Workflow: `.github/workflows/build-ai-llama.yml`.

**One-time setup (operator, through the Azure Portal — no CLI, no secrets):**

1. Upload the two GGUF shards to a blob container. In the deployment storage
   account, create a container named `ai-models` and upload (drag-and-drop):
   - `qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf`
   - `qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf`
   (Digests are pinned in `docs/ai010-selection/SELECTION.md`; the build
   re-verifies them.)
2. Grant the deploy OIDC app **Storage Blob Data Reader** on that container
   (Portal → the container → Access control (IAM) → Add role assignment → assign
   to the app whose client ID is the `AZURE_CLIENT_ID` environment variable).

**Build:** Actions → **Build ai-llama image** → Run workflow, with:
- `environment`: `staging`
- `acr_name`: your ACR name (`az acr list -g rg-kp-staging --query "[0].name" -o tsv`, or from the Portal)
- `storage_account`: the account holding `ai-models`

The run's summary prints the immutable `…/ai-llama@sha256:…` reference.

**Enable it:** in Settings → Environments → `staging`, set:
- `AI_LLAMA_IMAGE` = the image reference from the run summary
- `DEPLOY_AI_GATEWAY` = `true`

The gateway then provisions automatically during the `workloads` phase — no
extra ai-gateway step.

## Fallback: build on a host with the weights + a working `az`

If you have a host that holds the weights and can complete `az login` (e.g. a
machine where security defaults don't block CLI auth), run:

```
ACR=<acr-name> MODEL_DIR=<dir-with-the-two-gguf-shards> \
  ./scripts/operator/deployment-preflight/build-ai-llama-image.sh
```

It stages the weights, resolves+pins the llama.cpp base digest, builds in ACR,
and prints the same `gh variable set …` commands.

## Not yet exercised

Neither this image nor the `workloads` phase has been run end-to-end. Its first
real build/deploy is its first test — the same as bootstrap/finalize were.
