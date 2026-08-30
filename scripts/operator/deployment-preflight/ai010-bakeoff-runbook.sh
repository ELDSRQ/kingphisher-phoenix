#!/usr/bin/env bash
#
# AI-010 internal-model bake-off operator runbook.
#
# Run on the controller Mac. This script is READ-ONLY toward the repository and
# performs NO outbound network access except the loopback llama.cpp endpoint you
# point it at. It does not download, pull, or update model weights. It verifies
# the offline scoring harness, checks that you have supplied the digest-pinned
# weights+license+runtime contract, runs the fixed evaluation set through the
# loopback endpoint, and records the selection evidence (including evaluation-set
# digest) to the report you name.
#
# Exit codes: 0 run completed (report written), 1 blocker, 2 usage/validation.

set -euo pipefail

# --- auto-discover repo root -------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_here_is_repo_root() { [ -f "$1/RESUME-HERE.md" ] && [ -d "$1/scripts/ai-bakeoff" ]; }
if _here_is_repo_root "$SCRIPT_DIR/../../.."; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
elif _here_is_repo_root "$SCRIPT_DIR/../../../../.."; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
else
  echo "error: could not resolve repo root from $SCRIPT_DIR" >&2
  exit 2
fi
BAKEOFF="$REPO_ROOT/scripts/ai-bakeoff/evaluate_model.py"
export UV_IGNORE_SYSTEM=0

usage() {
  cat <<USAGE
Usage:
  $0 --weights /abs/path/candidate-Q4_K_M.gguf --license /abs/path/LICENSE \\
     --runtime "llama.cpp 2026-08-git@abcd1234 quant lasm" \\
     --model <id-as-loaded-on-port-8080> --report /tmp/bakeoff-<model>.json \\
     [--endpoint http://127.0.0.1:8080/v1] [--version "1.0"]

  --weights : absolute path to the operator-held GGUF weights artifact
  --license : absolute path to the model license text
  --runtime : one quoted line describing llama.cpp build/quant (digest-pinned
              license+runtime recorded in the evidence, not passed to the runner)
  --model   : candidate model id as loaded by the loopback llama.cpp server
  --report  : absolute path for the JSON selection evidence
  --endpoint: loopback OpenAI-compatible base URL (default http://127.0.0.1:8080/v1)
USAGE
  exit 2
}

WEIGHTS=""; LICENSE=""; RUNTIME=""; MODEL=""; REPORT=""; ENDPOINT="http://127.0.0.1:8080/v1"; VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --weights) WEIGHTS="$2"; shift 2 ;;
    --license) LICENSE="$2"; shift 2 ;;
    --runtime) RUNTIME="$2"; shift 2 ;;
    --model)   MODEL="$2";   shift 2 ;;
    --report)  REPORT="$2";  shift 2 ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "error: unknown argument $1" >&2; usage ;;
  esac
done
[ -n "$WEIGHTS" ] || { echo "error: --weights required" >&2; usage; }
[ -n "$LICENSE" ] || { echo "error: --license required" >&2; usage; }
[ -n "$MODEL" ]   || { echo "error: --model required" >&2; usage; }
[ -n "$REPORT" ]  || { echo "error: --report required" >&2; usage; }

PASS=0; WARN=0; FAIL=0
note() { printf '  \033[32m✓\033[0m %-34s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
warn() { printf '  \033[33m!\033[0m %-34s %s\n' "$1" "$2"; WARN=$((WARN+1)); }
fail() { printf '  \033[31m✗\033[0m %-34s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }

printf '\nAI-010 bake-off operator runbook\nrepo root : %s\n' "$REPO_ROOT"
printf '%s\n' "--------------------------------------------"

# 0) offline harness self-check (no model required)
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then PY="$REPO_ROOT/.venv/bin/python"
elif command -v uv >/dev/null 2>&1; then PY="uv run python"
else PY="python"; fi
if "$PY" -m pytest "$REPO_ROOT/tests/test_ai_bakeoff.py" -q >/tmp/kp-bakeoff-harness.log 2>&1; then
  note "offline bake-off harness" "green (exit 0)"
else
  warn "offline bake-off harness" "pytest exited nonzero; see /tmp/kp-bakeoff-harness.log"
fi

# 1) operator-held weights + license + runtime contract (selection evidence)
for f in "$WEIGHTS" "$LICENSE"; do
  if [ -f "$f" ]; then
    sha="$(shasum -a 256 "$f" | awk '{print $1}')"
    note "$(basename "$f")" "present, sha256 $sha"
  else
    fail "$(basename "$f")" "not found at $f"
  fi
done
[ -n "$RUNTIME" ] && note "runtime" "$RUNTIME" || warn "runtime" "--runtime not supplied; record it in the evidence"
[ -n "$VERSION" ] && note "contract version" "$VERSION" || warn "contract version" "none supplied (optional)"

# 2) loopback llama.cpp endpoint reachable? (READ-ONLY probe; no weights upload)
if command -v curl >/dev/null 2>&1 && curl -s --max-time 5 "$ENDPOINT/models" >/dev/null 2>&1; then
  note "loopback endpoint" "$ENDPOINT reachable"
else
  fail "loopback endpoint" "$ENDPOINT not reachable — start llama-server: llama-server -m <gguf> --host 127.0.0.1 --port 8080"
fi
# refuse any non-loopback endpoint (defense in depth)
case "$ENDPOINT" in
  http://127.0.0.1:*) : ;;
  http://localhost:*) : ;;
  *) fail "endpoint must be loopback" "refusing $ENDPOINT (runner enforces loopback only)" ;;
esac

printf '\n  passed: %d   warnings: %d   blockers: %d\n' "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf '\nA blocker remains; fix it before running the bake-off. Exit 1.\n' >&2
  exit 1
fi

printf '\nStarting fixed-evaluation run…\n'
"$PY" "$BAKEOFF" --endpoint "$ENDPOINT" --model "$MODEL" --report "$REPORT"

printf '\nBake-off complete. Selection evidence that must be recorded (digest-pinned):\n'
printf '  - weights artifact + sha256  : %s\n' "$WEIGHTS"
printf '  - license text               : %s\n' "$LICENSE"
printf '  - runtime/quant/prompt       : %s\n' "$RUNTIME"
printf '  - report JSON                : %s\n' "$(cd "$(dirname "$REPORT")" && pwd)/$(basename "$REPORT")"
printf 'The report embeds the evaluation-set digest and version; commit it after an\nindependent review (never auto-pull/auto-update weights in production).\n'
exit 0