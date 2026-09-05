#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# dr-sync.sh — Disaster-recovery sync of everything NOT in GitHub to Alice (.36)
#
# STANDING INSTRUCTION (part of the build/ops process):
#   Whenever the DR-relevant secrets change (project .env, ~/.ssh keys/config,
#   or the gh CLI auth), the current state is re-archived and mirrored to
#   192.168.1.36:phishing-platform-DR\.  This runs automatically via the
#   launchd watcher com.kingphisher.dr-sync (WatchPaths on those files); it can
#   also be run by hand at any time.  It is hash-guarded and idempotent — a run
#   whose guarded content is unchanged does nothing (so az-login / known_hosts
#   churn never triggers a needless push).  Use --force to push regardless.
#
#   User chose PLAINTEXT-on-LAN storage (2026-09-05).  To harden later, pipe the
#   tarball through `age -p` before scp and adjust RESTORE.md.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO="/Users/edierks/projects/codex-test/phishing-awareness-platform"
REMOTE="erikd@192.168.1.36"          # Windows host "Alice"
REMOTE_DIR="phishing-platform-DR"    # relative to C:\Users\erikd
STATE_DIR="$HOME/.kingphisher-dr"
LOG="$STATE_DIR/sync.log"
HASHFILE="$STATE_DIR/last-sync.hash"
FORCE="${1:-}"

mkdir -p "$STATE_DIR"
log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  $*" | tee -a "$LOG" >&2; }

# --- guard: hash only the stable, security-relevant content -----------------
guard_input() {
  shasum -a 256 "$REPO/.env" 2>/dev/null || true
  # ssh keys/config/authorized_keys — exclude volatile known_hosts + runtime dirs
  find "$HOME/.ssh" -maxdepth 1 -type f ! -name 'known_hosts*' -print0 2>/dev/null \
    | sort -z | xargs -0 shasum -a 256 2>/dev/null || true
  # gh auth
  find "$HOME/.config/gh" -type f -print0 2>/dev/null \
    | sort -z | xargs -0 shasum -a 256 2>/dev/null || true
}
GUARD="$(guard_input | shasum -a 256 | awk '{print $1}')"

if [ "$FORCE" != "--force" ] && [ -f "$HASHFILE" ] && [ "$(cat "$HASHFILE")" = "$GUARD" ]; then
  log "no change (guard=$GUARD) — skip"
  exit 0
fi

# --- build the archive ------------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
TMP="$(mktemp -d)"; STAGE="$TMP/kp-dr-${STAMP}"; OUT="$TMP/kp-dr-latest.tar.gz"
mkdir -p "$STAGE"/{env,ssh,gh,azure}
cp -p "$REPO/.env" "$STAGE/env/dot-env"
rsync -a --exclude 'agent/' --exclude 'cm/' "$HOME/.ssh/" "$STAGE/ssh/"
rsync -a "$HOME/.config/gh/" "$STAGE/gh/"
for f in azureProfile.json config clouds.config az.json az.sess az_survey.json msal_http_cache.bin; do
  [ -e "$HOME/.azure/$f" ] && cp -p "$HOME/.azure/$f" "$STAGE/azure/$f" || true
done
{
  echo "Kingphisher-Phoenix DR archive"
  echo "built:  $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(hostname)"
  echo "repo HEAD: $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo '?')"
  echo "guard hash: $GUARD"
  echo
  echo "env/dot-env -> \$REPO/.env | ssh/ -> ~/.ssh | gh/ -> ~/.config/gh | azure/ -> ~/.azure"
  echo "NOT included: repo (github), ai-llama GGUF (re-stage), data/ (rebuild from Azure),"
  echo "  Azure MSAL tokens (macOS Keychain -> re-run 'az login')."
} > "$STAGE/MANIFEST.txt"
cat > "$STAGE/RESTORE.md" <<'EOF'
# DR restore (new machine)
1. Install git, gh, az, docker CLI, age, rsync.
2. mkdir -p ~/.ssh ~/.config/gh ~/.azure && chmod 700 ~/.ssh
3. ssh/*   -> ~/.ssh/     then chmod 600 ~/.ssh/*_ed25519 ~/.ssh/config
   gh/*    -> ~/.config/gh/
   azure/* -> ~/.azure/   then `az login` (tokens are not in these files)
4. git clone git@github.com:ELDSRQ/kingphisher-phoenix.git ; drop env/dot-env back as <repo>/.env
5. Verify: gh auth status ; ssh erikd@192.168.1.105 whoami ; az account show
EOF
tar -czf "$OUT" -C "$STAGE" .
LOCAL_SHA="$(shasum -a 256 "$OUT" | awk '{print $1}')"

# --- mirror to Alice: rotate latest->previous, push, verify -----------------
ssh -o ConnectTimeout=10 "$REMOTE" "if not exist $REMOTE_DIR mkdir $REMOTE_DIR & if exist $REMOTE_DIR\\kp-dr-latest.tar.gz move /y $REMOTE_DIR\\kp-dr-latest.tar.gz $REMOTE_DIR\\kp-dr-previous.tar.gz >nul" 2>>"$LOG" || true
scp -o ConnectTimeout=10 "$OUT" "$REMOTE:$REMOTE_DIR/kp-dr-latest.tar.gz" >>"$LOG" 2>&1
REMOTE_SHA="$(ssh -o ConnectTimeout=10 "$REMOTE" "certutil -hashfile $REMOTE_DIR\\kp-dr-latest.tar.gz SHA256" 2>/dev/null | sed -n '2p' | tr -d ' \r')"

if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
  echo "$GUARD" > "$HASHFILE"
  log "SYNCED ok  sha=$LOCAL_SHA  size=$(wc -c <"$OUT")B -> $REMOTE:$REMOTE_DIR\\kp-dr-latest.tar.gz"
  rm -rf "$TMP"
  exit 0
else
  log "FAILED verify  local=$LOCAL_SHA  remote=$REMOTE_SHA  (state NOT advanced)"
  rm -rf "$TMP"
  exit 1
fi
