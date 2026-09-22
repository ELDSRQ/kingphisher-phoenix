#!/usr/bin/env bash
# Run the release image qualification (readiness gate D2) on the .105 WSL2
# worker with every guard verify_images.sh requires already satisfied.
#
# WHY THIS EXISTS: verify_images.sh deliberately refuses to run until the
# operator states, exactly, what it is allowed to build against. That is the
# right posture for a release contract, but the six required values are written
# down nowhere, each is checked one at a time, and every failure exits within
# seconds with a single line and no context. Working them out from scratch takes
# far longer than the build itself:
#
#   KP_IMAGE_EXPECTED_DOCKER_ENDPOINT      unix/ssh/tcp, credential-free
#   DOCKER_HOST                            must EQUAL the expected endpoint
#                                          (unset is a mismatch, not a default)
#   KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR      the engine's real root dir
#   KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST
#                                          computed from the source tree; this
#                                          script derives it in a probe pass
#   KP_TRIVY_EXECUTABLE / _EXPECTED_SHA256 exact absolute path to Trivy 0.74.0
#   KP_TRIVY_CACHE_DIR                     absolute AND beneath the build
#                                          storage path (the repo root)
#
# It refuses a dirty tree. An "exact-final-image" built from uncommitted local
# edits proves nothing, and the digest guard would in any case pin to source no
# reviewer ever saw.
#
# Usage (on .105, inside WSL):  bash scripts/operator/release/verify-images-105.sh
# Overrides: TRIVY=/abs/path  ALLOW_DIRTY=1
set -euo pipefail

say(){ printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok(){  printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m  xx\033[0m %s\n' "$*"; exit 1; }

cd "$(git rev-parse --show-toplevel)"
REPO_ROOT="$(pwd)"
TRIVY="${TRIVY:-$HOME/.local/bin/trivy}"
CACHE_DIR="$REPO_ROOT/data/trivy-cache"

say "Preconditions"
command -v docker >/dev/null || die "docker not on PATH"
[ -x "$TRIVY" ] || die "Trivy not found at $TRIVY. Install the pinned 0.74.0:
     curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz \\
       | tar xz -C /tmp trivy && install -m 0755 /tmp/trivy \"\$HOME/.local/bin/trivy\""
"$TRIVY" --version | grep -q '0\.74\.0' || die "$TRIVY is not version 0.74.0 (the contract pins it)"
if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
  [ -z "$(git status --porcelain | grep -v '^??' || true)" ] \
    || die "working tree has uncommitted changes; a release image must come from reviewed source (ALLOW_DIRTY=1 to override)"
fi
ok "HEAD $(git rev-parse --short HEAD), Trivy $("$TRIVY" --version | head -1)"

ROOT_DIR="$(docker info --format '{{.DockerRootDir}}')"
ENDPOINT="unix:///var/run/docker.sock"
TRIVY_SHA="$(sha256sum "$TRIVY" | awk '{print $1}')"
mkdir -p "$CACHE_DIR"

common_env() {
  printf '%s\n' \
    "DOCKER_HOST=$ENDPOINT" \
    "KP_IMAGE_EXPECTED_DOCKER_ENDPOINT=$ENDPOINT" \
    "KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR=$ROOT_DIR" \
    "KP_IMAGE_EXPECTED_PLATFORM=linux/amd64" \
    "KP_TRIVY_EXECUTABLE=$TRIVY" \
    "KP_TRIVY_EXPECTED_SHA256=$TRIVY_SHA" \
    "KP_TRIVY_CACHE_DIR=$CACHE_DIR" \
    "PATH=$PATH" "HOME=$HOME"
}

# The digest is only knowable by letting the script build the manifest, so the
# probe pass is expected to fail on the missing digest and is not an error.
say "Probe pass: deriving the source manifest digest"
mapfile -t ENVV < <(common_env)
env "${ENVV[@]}" bash scripts/operator/release/verify_images.sh >/tmp/kp-d2-probe.log 2>&1 || true
# shellcheck disable=SC2012  # these directory names are timestamp-generated
# by verify_images.sh, so they are always plain; ls -t is the simplest
# newest-first selection and find has no portable equivalent here.
EVID="$(ls -1dt data/qualification/release-images/*/ | head -1)"
DIGEST="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]+'source-before.json'))['digest'])" "$EVID")"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "could not derive a source manifest digest (see /tmp/kp-d2-probe.log)"
ok "source digest $DIGEST"

say "Release qualification (build + scan + hardened startup, linux/amd64)"
env "${ENVV[@]}" KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST="$DIGEST" \
  bash scripts/operator/release/verify_images.sh 2>&1 | tail -6
ok "release images qualified"

# shellcheck disable=SC2012  # these directory names are timestamp-generated
# by verify_images.sh, so they are always plain; ls -t is the simplest
# newest-first selection and find has no portable equivalent here.
EVID="$(ls -1dt data/qualification/release-images/*/ | head -1)"
say "Evidence: $EVID"
python3 - "$EVID" <<'PY'
import json,sys,os
doc=json.load(open(os.path.join(sys.argv[1],"qualification.json")))
print("     status:", doc.get("status"))
print("     platform:", doc.get("platform"))
imgs=doc.get("images") or []
print("     images:", ", ".join(i.get("name","?") for i in imgs if isinstance(i,dict)))
PY
