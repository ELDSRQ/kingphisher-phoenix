# WSL2 Docker qualification worker on `.105`

Additive counterpart to `../remote-docker-worker/` (the macOS/`.140`/Colima
worker). Nothing here edits or replaces the `.140` tooling; the two run in
parallel until `.105` is fully qualified and cut over. See the full risk-ordered
plan in `docs/migration/WSL2-105-MIGRATION-PLAN.md`.

Host: `erikd@192.168.1.105` — Windows 11, WSL2 (Ubuntu), Docker Engine native
in WSL2, `x86_64`, 64 GB RAM / 2 TB disk.

**Reviewed 2026-09-03 (read-only):** Ubuntu 24.04 WSL2, Docker 29.8 native linux/amd64 engine already running, ~48 GB to WSL2, 12 vCPU, ~952 GB free. Remaining gaps: `uv` and Python 3.13 (host has 3.12), repo not yet cloned.

**Access:** `ssh erikd@192.168.1.105` lands in Windows cmd; the engine is in WSL2, reached via `wsl -e bash` (tooling wraps this automatically via `KP_WSL_LAUNCH`). `.105` is a **shared host**; all tooling is scoped to the `phishing-awareness-platform` compose project and never touches other workloads. **While another agent is moving containers onto `.105`, make no Docker/WSL changes and do not reboot it.**

## Files
- `preflight-105.sh` — read-only controller-side qualification of `.105`.
- `restore-state-wsl2.sh` — clean-engine restore of the Phase 0 checkpoint (runs
  inside WSL2). Mirrors the proven `.140` restore verification; refuses a dirty
  target and refuses the `.140` Colima engine.
- `test-tooling.sh` — daemon-free static tests (syntax, shellcheck, compose
  parse, engine-guard unit test). Runnable on the Mac controller.

## Phase 1 — one-time `.105` bring-up (operator, on `.105`)
Run these in an **elevated PowerShell** on `.105`, then inside WSL2. Replace
nothing — these are the literal commands.

PowerShell (Windows):
```powershell
wsl --install -d Ubuntu
wsl --update
# ~/.wslconfig on the Windows user profile: generous memory + systemd
@"
[wsl2]
memory=48GB
processors=8
"@ | Set-Content -Encoding ascii $env:USERPROFILE\.wslconfig
wsl --shutdown
```

Inside WSL2 (Ubuntu shell):
```bash
# systemd on
sudo tee /etc/wsl.conf >/dev/null <<'EOF'
[boot]
systemd=true
EOF
# Docker Engine (native, in WSL2 — not Docker Desktop)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
# OpenSSH so the Mac controller can drive .105 like it drives .140
sudo apt-get update && sudo apt-get install -y openssh-server
sudo systemctl enable --now ssh docker
# uv + Python 3.13 toolchain
curl -LsSf https://astral.sh/uv/install.sh | sh
# repo on ext4 (NOT /mnt/c)
git clone <this-repo-url> ~/kingphisher-phoenix
```
Then exit and re-enter WSL2 so the `docker` group membership applies, and
authorize the controller's Ed25519 key in `~/.ssh/authorized_keys`.

## Phase 2 — qualify the host (controller, read-only)
```
KP_WSL2_HOST=edierks@192.168.1.105 scripts/operator/wsl2-docker-worker/preflight-105.sh
```

## Phase 3 — restore the Phase 0 checkpoint (on `.105`, inside WSL2)
Copy the encrypted Phase 0 snapshot to `.105`, decrypt into
`~/kingphisher-phoenix/migration-checkpoint/` (`postgres.dump` + `redis.rdb`), then:
```
cd ~/kingphisher-phoenix
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh           # dry preflight
scripts/operator/wsl2-docker-worker/restore-state-wsl2.sh --apply   # verified restore
```

## Phase 4 — qualification gates (on `.105`)
```
scripts/run-hermetic-tests.sh all
scripts/operator/base-image-qualification/run.sh --timeout-seconds 300
scripts/operator/e2e/run-e2e.sh        # point start-console at .105 (see plan §2 Phase 4)
```
`.105` must match `.140`'s pass set before cutover (Phase 5).

## Safety
- `.140` stays the source of truth until cutover; freeze (do not delete) it as a
  hot rollback through the soak window.
- The restore only ever targets a **clean** engine and refuses the `.140` engine.
- Run `test-tooling.sh` after any edit here.
