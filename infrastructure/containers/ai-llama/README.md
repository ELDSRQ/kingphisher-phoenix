# Building and deploying the ai-llama sidecar (Qwen in Azure)

This is **optional** and only needed to run Qwen inside Azure (the `workloads`
phase). Qwen already works locally via `docker compose --profile ai up
ai-gateway`. Nothing is broken without this.

The image bakes the digest-pinned `Qwen2.5-7B-Instruct-Q4_K_M` GGUF into a
pinned `llama.cpp` server. It is built on the `.140` worker because that host
holds the weights and has Docker; the CI release loop cannot build it (the
~4.7 GB weights are never in the checkout and never auto-downloaded).

## Everything below runs on the .140 worker (over SSH)

### 0. Checks (paste the output back if any line is empty or errors)

```
ls -la /Volumes/DockerExternal/KingPhisher-Phoenix/ai010-models/qwen2.5-7b-instruct/qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf
command -v az || echo "AZ-NOT-INSTALLED"
command -v git docker || echo "TOOL-MISSING"
```

### 1. Sign in to Azure (device-code flow works over SSH)

```
az login --use-device-code
az account set --subscription 169644fd-c81d-4935-af55-5770f8271022
```

### 2. Get a writable checkout (the mounted source is read-only)

```
rm -rf ~/kp-ai-llama-build
git clone https://github.com/ELDSRQ/kingphisher-phoenix.git ~/kp-ai-llama-build
cd ~/kp-ai-llama-build
```

### 3. Find the ACR name

```
az acr list -g rg-kp-staging --query "[0].name" -o tsv
```

### 4. Build and push (uploads the ~4.7 GB context to ACR; slow)

Replace `<ACR-NAME>` with the value from step 3:

```
ACR=<ACR-NAME> ./scripts/operator/deployment-preflight/build-ai-llama-image.sh
```

The script stages the weights, resolves and pins the llama.cpp base digest,
builds in ACR, and prints the two `gh variable set` commands.

### 5. Enable the gateway for the deploy

Run the two `gh variable set ...` commands the script printed (they set
`AI_LLAMA_IMAGE` to the built digest and `DEPLOY_AI_GATEWAY=true`). If `gh` is
not signed in on `.140`, run them on your Mac instead — they only touch GitHub.

### 6. Deploy

Deploying the gateway happens as part of the `workloads` phase, which is a
larger operator-gated deploy with its own prerequisites (all release images
built, migration run, health gates). Do this when you take on the workloads
phase; at that point the gateway is provisioned automatically because
`DEPLOY_AI_GATEWAY=true` and `AI_LLAMA_IMAGE` are set.
