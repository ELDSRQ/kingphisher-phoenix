# Task: Set up automatic disaster-recovery (DR) sync of this project's non-Git secrets

> Reusable prompt to hand to an AI session on ANY project so it reproduces the DR
> auto-sync pattern. It discovers each project's own specifics rather than hardcoding.

GOAL: A laptop/workstation failure must not lose anything that isn't already in
GitHub. Create a self-maintaining backup that mirrors every secret/credential/local
state file NOT tracked in Git to a designated backup host, and RE-syncs automatically
whenever those files change.

## Step 1 — Discover what's NOT in Git (don't assume; enumerate)
- Read `.gitignore` and run `git status --ignored` to find ignored/untracked files.
- Identify the real irreplaceable items, typically: project `.env`/secret files,
  `~/.ssh/` (private keys, config, known_hosts), CLI auth tokens (`~/.config/gh`,
  `~/.azure` profile, `~/.aws`, `~/.kube`, etc.), Terraform state if local, and any
  local secret material. EXCLUDE anything regenerable or already in Git: virtualenvs,
  node_modules, caches, build output, large re-downloadable model/blob files, and
  files/dirs that are actually tracked (verify with `git ls-files`).
- Show me the proposed include/exclude list with sizes before building anything.

## Step 2 — Ask me two decisions
1. Destination host + folder for the DR copy (and confirm it's reachable, e.g. an ssh
   round-trip). Probe its OS — the transfer/verify commands differ on Windows vs Linux.
2. Protection: encrypted (recommended — e.g. `age -p` passphrase I own) vs plaintext.
   Flag explicitly that an unencrypted bundle of all my private keys makes the backup
   host's security equal to this machine's.

## Step 3 — Build a hash-guarded sync script (idempotent, self-verifying)
Write a tracked script (e.g. `scripts/ops/dr-sync.sh`) that:
- Assembles the include-set into a staging dir, writes a MANIFEST + RESTORE notes
  (how to put each item back on a fresh machine), and tars it.
- Is HASH-GUARDED: computes a hash over only the STABLE, security-relevant content and
  skips the whole push if unchanged. CRITICAL: exclude high-churn files from the guard
  (e.g. `known_hosts`, token caches that rewrite on every CLI call) or the watcher will
  fire constantly and spam pushes. Support a `--force` flag to override.
- Mirrors to the backup host as a stable `…-latest` filename, rotating the previous
  copy to `…-previous` first (keep 1–2 generations; this is a mirror, not history).
- VERIFIES integrity after transfer (compare SHA-256 of the remote copy vs local) and
  only advances the stored "last-synced" hash on a verified success. Logs to a state dir.

## Step 4 — Install an automatic trigger (whenever the secrets change)
- macOS: a `launchd` LaunchAgent with `WatchPaths` on the secret files/dirs → runs the
  script. (`ThrottleInterval`, RunAtLoad=false, log to a file.)
- Linux: a systemd `path` unit (`PathModified=`/`PathChanged=`) → oneshot service, or a
  cron fallback.
- Keep the trigger definition version-controlled alongside the script.

## Step 5 — Seed once and verify
- Do a first `--force` run to prove the whole path end-to-end; confirm the verified-OK
  line and that the file exists on the backup host.
- Confirm the watcher is loaded/armed and idle.

## Design requirements / gotchas to honor
- Idempotent + hash-guarded so routine tool churn never triggers a needless push.
- Verify-after-copy; never mark "synced" without a matching remote checksum.
- Keep the backup a MIRROR of current state (latest + one previous), not an ever-growing pile.
- The backup includes brand-new keys automatically once added — intended, but tell me so.
- It's a point-in-time snapshot between triggers; the auto-trigger is what keeps it current.

## Note on AI safety guardrails (expect this)
Bundling private keys and pushing them off-machine, and installing a background agent
that does so repeatedly, is "exfiltration-shaped" — your execution sandbox will likely
BLOCK you from running the push or writing the auto-start agent yourself. That's correct
behavior. Build and commit all the files, then hand me the exact 2–3 commands to install
the watcher and run the first seed myself. The watcher then runs as me, unaffected.

---
Reference implementation (this project): `scripts/operator/dr-sync.sh` +
`scripts/operator/com.kingphisher.dr-sync.plist`.
