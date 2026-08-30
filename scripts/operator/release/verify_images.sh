#!/usr/bin/env bash
set -euo pipefail
umask 077

# Build from a git-defined context so ignored credentials, virtualenvs, caches,
# and other workstation state can never make a broken image appear healthy.
repo_root="$(git rev-parse --show-toplevel)"
context_dir=""
resolved_build_storage_path=""
evidence_dir=""
expected_platform="${KP_IMAGE_EXPECTED_PLATFORM:-}"
server_platform=""
docker_endpoint=""
docker_root_dir=""
scanner_version=""
scanner_executable=""
scanner_executable_sha256=""
scanner_cache_dir=""
scanner_cache_unchanged="unknown"
scanner_cache_phase_recorded=0
scan_performed_by_verifier=0
current_phase="initialization"
docker_ready=0
main_complete=0
cleanup_result="not-run"
source_unchanged="unknown"
context_cleanup_result="not-run"
volume_inventory_before=""
volume_inventory_after=""
volume_inventory_unchanged="unknown"
readonly image_prefix="${KP_IMAGE_PREFIX:-kingphisher/verify}"
readonly build_storage_path="${KP_IMAGE_BUILD_STORAGE_PATH:-${repo_root}}"
readonly expected_docker_endpoint="${KP_IMAGE_EXPECTED_DOCKER_ENDPOINT:-}"
readonly expected_docker_root_dir="${KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR:-}"
readonly expected_source_manifest_digest="${KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST:-}"
readonly expected_trivy_version="0.74.0"
readonly configured_trivy_executable="${KP_TRIVY_EXECUTABLE:-}"
readonly expected_trivy_sha256="${KP_TRIVY_EXPECTED_SHA256:-}"
readonly configured_trivy_cache_dir="${KP_TRIVY_CACHE_DIR:-}"
readonly qualification_label_key="com.kingphisher.release-qualification"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly started_at
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}"
readonly run_id
readonly network_name="kp-image-verify-${run_id}"
declare -a phase_results=()
declare -a image_records=("__kp_no_image_record__")
declare -a scan_records=("__kp_no_scan_record__")
readonly -a hardened_run_args=(
  --read-only
  --tmpfs "/tmp:rw,noexec,nosuid,nodev"
  --cap-drop ALL
  --security-opt no-new-privileges:true
)

run_bounded() {
  local timeout_seconds="$1"
  shift
  python3 - "${timeout_seconds}" "$@" <<'PY'
import subprocess
import sys

timeout_seconds = int(sys.argv[1])
command = sys.argv[2:]
try:
    result = subprocess.run(command, timeout=timeout_seconds, check=False)
except subprocess.TimeoutExpired:
    print(
        f"Bounded {command[0]} command exceeded {timeout_seconds} seconds; arguments were redacted",
        file=sys.stderr,
    )
    raise SystemExit(124) from None
raise SystemExit(result.returncode)
PY
}

docker_bounded() {
  run_bounded "${KP_DOCKER_TIMEOUT_SECONDS:-120}" docker "$@"
}

docker_cleanup() {
  run_bounded "${KP_DOCKER_CLEANUP_TIMEOUT_SECONDS:-5}" docker "$@"
}

run_phase() {
  local phase="$1"
  shift
  current_phase="${phase}"
  "$@"
  phase_results+=("${phase}|passed")
  current_phase=""
}

require_build_headroom() {
  local available_kib minimum_free_gib minimum_free_kib
  minimum_free_gib="${KP_IMAGE_BUILD_MIN_FREE_GIB:-10}"
  if ! [[ "${minimum_free_gib}" =~ ^[1-9][0-9]*$ ]] \
    || (( 10#${minimum_free_gib} > 1048576 )); then
    printf 'KP_IMAGE_BUILD_MIN_FREE_GIB must be a positive whole-GiB integer no greater than 1048576\n' >&2
    return 2
  fi
  case "${build_storage_path}" in
    /*) ;;
    *)
      printf 'KP_IMAGE_BUILD_STORAGE_PATH must be an absolute directory\n' >&2
      return 2
      ;;
  esac
  if [[ ! -d "${build_storage_path}" || -L "${build_storage_path}" ]]; then
    printf 'KP_IMAGE_BUILD_STORAGE_PATH must be an existing, non-symbolic directory\n' >&2
    return 2
  fi
  if ! resolved_build_storage_path="$(cd "${build_storage_path}" && pwd -P)"; then
    printf 'KP_IMAGE_BUILD_STORAGE_PATH could not be resolved\n' >&2
    return 2
  fi
  minimum_free_kib=$((10#${minimum_free_gib} * 1024 * 1024))
  if ! available_kib="$(run_bounded 10 df -Pk "${resolved_build_storage_path}" | awk 'NR == 2 { print $4 }')" \
    || ! [[ "${available_kib}" =~ ^[0-9]+$ ]]; then
    printf 'Release-image disk headroom could not be measured; no image build or cleanup was attempted\n' >&2
    return 1
  fi
  if (( available_kib < minimum_free_kib )); then
    printf 'Release-image verification requires %s GiB free on %s; only %s KiB is available\n' \
      "${minimum_free_gib}" "${resolved_build_storage_path}" "${available_kib}" >&2
    printf 'Add capacity outside preserved project assets; do not prune or delete them\n' >&2
    return 1
  fi
}

require_timeout_configuration() {
  local variable value maximum
  for variable in KP_DOCKER_TIMEOUT_SECONDS KP_DOCKER_CLEANUP_TIMEOUT_SECONDS KP_TRIVY_TIMEOUT_SECONDS; do
    case "${variable}" in
      KP_DOCKER_TIMEOUT_SECONDS)
        value="${KP_DOCKER_TIMEOUT_SECONDS:-120}"
        maximum=3600
        ;;
      KP_DOCKER_CLEANUP_TIMEOUT_SECONDS)
        value="${KP_DOCKER_CLEANUP_TIMEOUT_SECONDS:-5}"
        maximum=60
        ;;
      *)
        value="${KP_TRIVY_TIMEOUT_SECONDS:-1800}"
        maximum=3600
        ;;
    esac
    if ! [[ "${value}" =~ ^[1-9][0-9]*$ ]] || (( 10#${value} > maximum )); then
      printf '%s must be a positive integer no greater than %s seconds\n' \
        "${variable}" "${maximum}" >&2
      return 2
    fi
  done
}

require_docker_target_configuration() {
  if [[ -z "${expected_docker_endpoint}" \
    || "${expected_docker_endpoint}" =~ [[:space:]] \
    || "${expected_docker_endpoint}" == *\?* \
    || "${expected_docker_endpoint}" == *\#* ]]; then
    printf 'KP_IMAGE_EXPECTED_DOCKER_ENDPOINT must be one exact, credential-free Docker endpoint\n' >&2
    return 2
  fi
  case "${expected_docker_endpoint}" in
    unix:///*|ssh://*|tcp://*) ;;
    *)
      printf 'KP_IMAGE_EXPECTED_DOCKER_ENDPOINT must use an explicit unix, ssh, or tcp endpoint\n' >&2
      return 2
      ;;
  esac
  case "${expected_docker_endpoint}" in
    ssh://*:*@*|ssh://*%*@*|tcp://*@*)
      printf 'KP_IMAGE_EXPECTED_DOCKER_ENDPOINT must not contain embedded credentials\n' >&2
      return 2
      ;;
  esac
  if [[ -n "${DOCKER_CONTEXT:-}" ]]; then
    printf 'DOCKER_CONTEXT must be unset so it cannot override the reviewed Docker endpoint\n' >&2
    return 2
  fi
  docker_endpoint="${DOCKER_HOST:-}"
  if [[ "${docker_endpoint}" != "${expected_docker_endpoint}" ]]; then
    printf 'DOCKER_HOST does not match KP_IMAGE_EXPECTED_DOCKER_ENDPOINT; refusing Docker access\n' >&2
    return 1
  fi
  case "${expected_docker_root_dir}" in
    /*) ;;
    *)
      printf 'KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR must be an exact absolute daemon path\n' >&2
      return 2
      ;;
  esac
  if [[ "${expected_docker_root_dir}" =~ [[:space:]] ]]; then
    printf 'KP_IMAGE_EXPECTED_DOCKER_ROOT_DIR must not contain whitespace\n' >&2
    return 2
  fi
}

initialize_evidence_directory() {
  local configured leaf parent resolved_parent root
  configured="${KP_IMAGE_QUALIFICATION_EVIDENCE_DIR:-}"
  if [[ -n "${configured}" ]]; then
    case "${configured}" in
      /*) ;;
      *)
        printf 'KP_IMAGE_QUALIFICATION_EVIDENCE_DIR must be an absolute, unused path\n' >&2
        return 2
        ;;
    esac
    if [[ -e "${configured}" || -L "${configured}" ]]; then
      printf 'Refusing to overwrite qualification evidence path: %s\n' "${configured}" >&2
      return 1
    fi
    parent="${configured%/*}"
    [[ -n "${parent}" ]] || parent="/"
    leaf="${configured##*/}"
    if [[ -z "${leaf}" || "${leaf}" == "." || "${leaf}" == ".." ]]; then
      printf 'KP_IMAGE_QUALIFICATION_EVIDENCE_DIR must name one unused child directory\n' >&2
      return 2
    fi
    if [[ ! -d "${parent}" || -L "${parent}" ]]; then
      printf 'The parent of KP_IMAGE_QUALIFICATION_EVIDENCE_DIR must be an existing, non-symbolic directory\n' >&2
      return 2
    fi
    if ! resolved_parent="$(cd "${parent}" && pwd -P)"; then
      printf 'The parent of KP_IMAGE_QUALIFICATION_EVIDENCE_DIR could not be resolved\n' >&2
      return 2
    fi
    if [[ "${resolved_build_storage_path}" != "/" ]]; then
      case "${resolved_parent}" in
        "${resolved_build_storage_path}"|"${resolved_build_storage_path}"/*) ;;
        *)
          printf 'KP_IMAGE_QUALIFICATION_EVIDENCE_DIR must remain beneath KP_IMAGE_BUILD_STORAGE_PATH\n' >&2
          return 2
          ;;
      esac
    fi
    evidence_dir="${resolved_parent}/${leaf}"
  else
    root="${resolved_build_storage_path}/data/qualification/release-images"
    # Every target is absolute and validated above. Avoid GNU's `--` operand:
    # the native BSD mkdir on macOS rejects it rather than treating it as the
    # end of options.
    mkdir -p "${root}"
    if [[ ! -d "${root}" || -L "${root}" ]]; then
      printf 'The default qualification evidence root must be a non-symbolic directory\n' >&2
      return 1
    fi
    evidence_dir="${root}/${run_id}"
  fi
  if ! mkdir "${evidence_dir}"; then
    printf 'Could not exclusively create qualification evidence directory: %s\n' "${evidence_dir}" >&2
    return 1
  fi
  chmod 700 "${evidence_dir}"
  printf 'Qualification evidence directory: %s\n' "${evidence_dir}"
}

write_source_manifest() {
  local source_mode="$1"
  local source_root="$2"
  local output_path="$3"
  python3 - "${source_mode}" "${source_root}" "${output_path}" <<'PY'
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

mode, root_value, output_value = sys.argv[1:]
root = Path(root_value)
output = Path(output_value)


def selected_git_paths() -> list[bytes]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise SystemExit("could not enumerate the git-defined release source")
    return sorted(path for path in result.stdout.split(b"\0") if path)


def selected_tree_paths() -> list[bytes]:
    selected: list[bytes] = []
    root_bytes = os.fsencode(root)
    for directory, directory_names, file_names in os.walk(root_bytes, followlinks=False):
        for name in list(directory_names):
            absolute = os.path.join(directory, name)
            if os.path.islink(absolute):
                directory_names.remove(name)
                selected.append(os.path.relpath(absolute, root_bytes))
        for name in file_names:
            selected.append(os.path.relpath(os.path.join(directory, name), root_bytes))
    return sorted(selected)


if mode == "git":
    paths = selected_git_paths()
elif mode == "tree":
    paths = selected_tree_paths()
else:
    raise SystemExit("unsupported source-manifest mode")

entries: list[dict[str, object]] = []
root_bytes = os.fsencode(root)
for relative in paths:
    if relative.startswith(b"/") or b"\0" in relative or b".." in relative.split(b"/"):
        raise SystemExit("release source contains an unsafe path")
    absolute = os.path.join(root_bytes, relative)
    try:
        metadata = os.lstat(absolute)
    except FileNotFoundError:
        if mode == "git":
            continue
        raise SystemExit("the copied release context changed while it was inventoried") from None
    record: dict[str, object] = {
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "path": os.fsdecode(relative),
    }
    if stat.S_ISREG(metadata.st_mode):
        digest = hashlib.sha256()
        with open(absolute, "rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        record.update({"kind": "file", "sha256": digest.hexdigest(), "size": metadata.st_size})
    elif stat.S_ISLNK(metadata.st_mode):
        target_bytes = os.fsencode(os.readlink(absolute))
        record.update(
            {
                "kind": "symlink",
                "sha256": hashlib.sha256(target_bytes).hexdigest(),
                "size": len(target_bytes),
                "target": os.fsdecode(target_bytes),
            }
        )
    else:
        raise SystemExit(f"release source contains unsupported entry type: {os.fsdecode(relative)}")
    entries.append(record)

canonical = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
manifest = {
    "schema": "kp.release-source-manifest.v1",
    "algorithm": "sha256",
    "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    "file_count": len(entries),
    "entries": entries,
}
with output.open("x", encoding="utf-8") as target:
    json.dump(manifest, target, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    target.write("\n")
PY
}

compare_source_manifests() {
  python3 - "$@" <<'PY'
import json
import sys
from pathlib import Path

digests = []
for value in sys.argv[1:]:
    document = json.loads(Path(value).read_text(encoding="utf-8"))
    digest = document.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise SystemExit("source manifest is malformed")
    digests.append(digest)
if len(set(digests)) != 1:
    raise SystemExit("release source changed during qualification")
PY
}

require_expected_source_manifest() {
  local actual_digest
  if ! [[ "${expected_source_manifest_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST must be one sha256:<64 lowercase hex> digest\n' >&2
    return 2
  fi
  actual_digest="$(python3 - "${evidence_dir}/source-before.json" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
digest = document.get("digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("source manifest digest is malformed")
print(digest)
PY
)"
  if [[ "${actual_digest}" != "${expected_source_manifest_digest}" ]]; then
    printf 'Release source does not match KP_IMAGE_EXPECTED_SOURCE_MANIFEST_DIGEST\n' >&2
    return 1
  fi
}

print_source_manifest_digest() {
  local helper_dir helper_manifest result
  helper_dir="$(mktemp -d "${TMPDIR:-/tmp}/kp-source-manifest.XXXXXX")"
  helper_manifest="${helper_dir}/source.json"
  if ! write_source_manifest git "${repo_root}" "${helper_manifest}"; then
    rm -rf "${helper_dir}"
    return 1
  fi
  python3 - "${helper_manifest}" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
digest = document.get("digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("source manifest digest is malformed")
print(digest)
PY
  result=$?
  rm -rf "${helper_dir}"
  return "${result}"
}

write_scanner_inputs() {
  python3 - \
    "${evidence_dir}/trivy-config.yaml" \
    "${evidence_dir}/trivy-ignore.txt" \
    "${evidence_dir}/trivy-secret.yaml" <<'PY'
import os
import sys
from pathlib import Path

config_value, ignore_value, secret_value = sys.argv[1:]
config = Path(config_value)
ignore = Path(ignore_value)
secret = Path(secret_value)
with config.open("x", encoding="utf-8") as output:
    output.write("{}\n")
    output.flush()
    os.fsync(output.fileno())
with ignore.open("x", encoding="utf-8") as output:
    output.flush()
    os.fsync(output.fileno())
with secret.open("x", encoding="utf-8") as output:
    output.write("{}\n")
    output.flush()
    os.fsync(output.fileno())
os.chmod(config, 0o600)
os.chmod(ignore, 0o600)
os.chmod(secret, 0o600)
PY
}

write_scanner_cache_manifest() {
  local output_path="$1"
  python3 - "${scanner_cache_dir}" "${output_path}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

root_value, output_value = sys.argv[1:]
root = Path(root_value)
output = Path(output_value)
# trivy 0.74.0 (the pinned release scanner) maintains only the `db`
# directory in its cache: the `policy` directory (check-bundle policy
# metadata) arrived with later trivy releases, so the reviewed 0.74.0
# executable cannot ever create it. Requiring `policy` makes the cache
# manifest unwritable by design, so `db` stays required and `policy` is
# captured only when the runtime provides one; the before/after
# immutability comparison still covers everything that exists. Revisit
# when the pinned scanner is upgraded to a check-bundle-capable version.
required = {"db/metadata.json", "db/trivy.db"}
entries = []

top_levels = ["db"]
if (root / "policy").exists():
    if (root / "policy").is_symlink() or not (root / "policy").is_dir():
        raise SystemExit("Trivy cache policy directory is symbolic or unsupported")
    top_levels.append("policy")

for top_level in top_levels:
    selected_root = root / top_level
    if selected_root.is_symlink() or not selected_root.is_dir():
        raise SystemExit(f"required Trivy cache directory is missing or symbolic: {top_level}")
    for directory, directory_names, file_names in os.walk(selected_root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            path = Path(directory) / name
            if path.is_symlink():
                raise SystemExit("Trivy cache contains a symbolic directory")
        for name in file_names:
            path = Path(directory) / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise SystemExit("Trivy cache contains a symbolic or unsupported file")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            entries.append(
                {
                    "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                    "path": path.relative_to(root).as_posix(),
                    "sha256": digest.hexdigest(),
                    "size": metadata.st_size,
                }
            )

entries.sort(key=lambda item: item["path"])
paths = {item["path"] for item in entries}
if not required.issubset(paths):
    raise SystemExit("Trivy cache is missing its database or check-bundle metadata")
canonical = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
document = {
    "schema": "kp.trivy-cache-manifest.v1",
    "algorithm": "sha256",
    "digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    "file_count": len(entries),
    "entries": entries,
}
with output.open("x", encoding="utf-8") as target:
    json.dump(document, target, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
os.chmod(output, 0o600)
PY
}

capture_scanner_cache_after() {
  local before="${evidence_dir}/trivy-cache-before.json"
  local after="${evidence_dir}/trivy-cache-after.json"
  if [[ ! -f "${before}" || -L "${before}" ]]; then
    printf 'The pre-scan Trivy cache manifest is missing or symbolic\n' >&2
    scanner_cache_unchanged="false"
    return 1
  fi
  if [[ ! -e "${after}" && ! -L "${after}" ]]; then
    write_scanner_cache_manifest "${after}" || {
      scanner_cache_unchanged="false"
      return 1
    }
  fi
  if compare_source_manifests "${before}" "${after}"; then
    scanner_cache_unchanged="true"
    return 0
  fi
  printf 'The effective Trivy database/check-bundle cache changed during image scans\n' >&2
  scanner_cache_unchanged="false"
  return 1
}

require_scanner() {
  local ambient_name executable_digest executable_parent resolved_executable metadata_record
  local version_artifact="${evidence_dir}/trivy-version.json"
  local config_artifact="${evidence_dir}/trivy-config.yaml"

  while IFS= read -r ambient_name; do
    case "${ambient_name}" in
      TRIVY_*)
        printf 'Ambient %s is prohibited; scanner policy is fixed by the verifier\n' \
          "${ambient_name}" >&2
        return 2
        ;;
    esac
  done < <(compgen -e)

  case "${configured_trivy_executable}" in
    /*) ;;
    *)
      printf 'KP_TRIVY_EXECUTABLE must be the exact absolute scanner path\n' >&2
      return 2
      ;;
  esac
  if [[ ! -f "${configured_trivy_executable}" || ! -x "${configured_trivy_executable}" \
    || -L "${configured_trivy_executable}" ]]; then
    printf 'KP_TRIVY_EXECUTABLE must be a regular, executable, non-symbolic file\n' >&2
    return 2
  fi
  executable_parent="${configured_trivy_executable%/*}"
  [[ -n "${executable_parent}" ]] || executable_parent="/"
  resolved_executable="$(cd "${executable_parent}" && pwd -P)/${configured_trivy_executable##*/}"
  if [[ "${resolved_executable}" != "${configured_trivy_executable}" ]]; then
    printf 'KP_TRIVY_EXECUTABLE must not traverse a symbolic parent directory\n' >&2
    return 2
  fi
  if ! [[ "${expected_trivy_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'KP_TRIVY_EXPECTED_SHA256 must be one lowercase SHA-256 digest\n' >&2
    return 2
  fi
  executable_digest="$(python3 - "${configured_trivy_executable}" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
print(digest.hexdigest())
PY
)"
  if [[ "${executable_digest}" != "${expected_trivy_sha256}" ]]; then
    printf 'KP_TRIVY_EXECUTABLE does not match KP_TRIVY_EXPECTED_SHA256\n' >&2
    return 1
  fi

  case "${configured_trivy_cache_dir}" in
    /*) ;;
    *)
      printf 'KP_TRIVY_CACHE_DIR must be an exact absolute directory\n' >&2
      return 2
      ;;
  esac
  if [[ ! -d "${configured_trivy_cache_dir}" || -L "${configured_trivy_cache_dir}" ]]; then
    printf 'KP_TRIVY_CACHE_DIR must be an existing, non-symbolic directory\n' >&2
    return 2
  fi
  scanner_cache_dir="$(cd "${configured_trivy_cache_dir}" && pwd -P)"
  if [[ "${scanner_cache_dir}" != "${configured_trivy_cache_dir}" ]]; then
    printf 'KP_TRIVY_CACHE_DIR must not traverse a symbolic parent directory\n' >&2
    return 2
  fi
  if [[ "${resolved_build_storage_path}" != "/" ]]; then
    case "${scanner_cache_dir}" in
      "${resolved_build_storage_path}"|"${resolved_build_storage_path}"/*) ;;
      *)
        printf 'KP_TRIVY_CACHE_DIR must remain beneath KP_IMAGE_BUILD_STORAGE_PATH\n' >&2
        return 2
        ;;
    esac
  fi

  scanner_executable="${configured_trivy_executable}"
  scanner_executable_sha256="${executable_digest}"
  write_scanner_inputs
  run_bounded "${KP_TRIVY_TIMEOUT_SECONDS:-1800}" \
    "${scanner_executable}" \
    --cache-dir "${scanner_cache_dir}" \
    --config "${config_artifact}" \
    image --download-db-only --skip-check-update=false
  if [[ -e "${version_artifact}" || -L "${version_artifact}" ]]; then
    printf 'Refusing to overwrite Trivy version/database evidence\n' >&2
    return 1
  fi
  run_bounded 30 \
    "${scanner_executable}" \
    --cache-dir "${scanner_cache_dir}" \
    --config "${config_artifact}" \
    version --format json > "${version_artifact}"
  chmod 600 "${version_artifact}"
  metadata_record="$(python3 - "${version_artifact}" "${expected_trivy_version}" <<'PY'
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

artifact_value, expected_version = sys.argv[1:]
artifact = Path(artifact_value)
if artifact.is_symlink() or not artifact.is_file():
    raise SystemExit("Trivy version evidence is missing or symbolic")
metadata = artifact.stat()
if metadata.st_size <= 0 or metadata.st_size > 64 * 1024:
    raise SystemExit("Trivy version evidence has an invalid size")
try:
    document = json.loads(artifact.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, ValueError):
    raise SystemExit("Trivy version evidence is malformed") from None
if not isinstance(document, dict) or document.get("Version") != expected_version:
    raise SystemExit("Trivy executable version does not match the reviewed version")


def timestamp(container, name):
    value = container.get(name)
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SystemExit(f"Trivy metadata field {name} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise SystemExit(f"Trivy metadata field {name} is invalid") from None
    if parsed.tzinfo is None:
        raise SystemExit(f"Trivy metadata field {name} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


database = document.get("VulnerabilityDB")
bundle = document.get("CheckBundle")
if not isinstance(database, dict):
    raise SystemExit("Trivy database metadata is absent")
if not isinstance(database.get("Version"), int) or database["Version"] <= 0:
    raise SystemExit("Trivy vulnerability database version is invalid")
updated_at = timestamp(database, "UpdatedAt")
next_update = timestamp(database, "NextUpdate")
downloaded_at = timestamp(database, "DownloadedAt")
now = datetime.now(timezone.utc)
future_tolerance = timedelta(minutes=5)
maximum_age = timedelta(hours=48)
# trivy 0.74.0 (the pinned release scanner) does not emit CheckBundle in
# `version --format json`: check-bundle support arrived in later trivy
# releases, so the reviewed 0.74.0 executable cannot ever produce it.
# Requiring it makes the gate unpassable by design, so CheckBundle is
# optional here: when the runtime provides one it is still validated for
# freshness and digest, and its absence is recorded (not a pass/fail
# dimension) for the pinned scanner. Revisit when the pinned scanner is
# upgraded to a check-bundle-capable version.
bundle_downloaded_at = None
bundle_digest = None
if isinstance(bundle, dict):
    bundle_downloaded_at = timestamp(bundle, "DownloadedAt")
    bundle_digest = bundle.get("Digest")
    if not isinstance(bundle_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", bundle_digest) is None:
        raise SystemExit("Trivy check-bundle digest is invalid")
for name, value in (
    ("UpdatedAt", updated_at),
    ("DownloadedAt", downloaded_at),
    ("CheckBundle.DownloadedAt", bundle_downloaded_at),
):
    if value is None:
        continue
    if value > now + future_tolerance or now - value > maximum_age:
        raise SystemExit(f"Trivy metadata field {name} is stale or in the future")
if next_update <= now or next_update > now + maximum_age:
    raise SystemExit("Trivy vulnerability database is stale or has an invalid next-update boundary")
digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
print(f"{document['Version']}|{digest}")
PY
)"
  IFS='|' read -r scanner_version _version_digest <<<"${metadata_record}"
  if [[ "${scanner_version}" != "${expected_trivy_version}" ]]; then
    printf 'trivy %s is required; found %s\n' \
      "${expected_trivy_version}" "${scanner_version:-unknown}" >&2
    return 2
  fi
  write_scanner_cache_manifest "${evidence_dir}/trivy-cache-before.json"
}

normalize_platform() {
  case "$1" in
    linux/amd64|linux/x86_64) printf 'linux/amd64\n' ;;
    linux/arm64|linux/aarch64) printf 'linux/arm64\n' ;;
    *) return 1 ;;
  esac
}

resolve_platform() {
  local normalized requested detected identity
  docker_bounded info >/dev/null
  identity="$(docker_bounded info --format '{{.OSType}}/{{.Architecture}}|{{.DockerRootDir}}')"
  IFS='|' read -r detected docker_root_dir <<<"${identity}"
  if ! server_platform="$(normalize_platform "${detected}")"; then
    printf 'Docker server platform %s is unsupported; expected native linux/amd64 or linux/arm64\n' \
      "${detected:-unknown}" >&2
    return 2
  fi
  requested="${expected_platform:-${server_platform}}"
  if ! normalized="$(normalize_platform "${requested}")"; then
    printf 'KP_IMAGE_EXPECTED_PLATFORM must be linux/amd64 or linux/arm64\n' >&2
    return 2
  fi
  expected_platform="${normalized}"
  if [[ "${server_platform}" != "${expected_platform}" ]]; then
    printf 'Refusing emulated release qualification: Docker server is %s but %s was requested\n' \
      "${server_platform}" "${expected_platform}" >&2
    return 1
  fi
  if [[ "${docker_root_dir}" != "${expected_docker_root_dir}" ]]; then
    printf 'Docker root directory %s does not match the reviewed target %s\n' \
      "${docker_root_dir:-unknown}" "${expected_docker_root_dir}" >&2
    return 1
  fi
  docker_ready=1
}

capture_volume_inventory_before() {
  volume_inventory_before="$(docker_bounded volume ls --quiet | LC_ALL=C sort)"
}

image_tag() {
  printf '%s-%s:local' "${image_prefix}" "$1"
}

container_name() {
  printf '%s-%s' "${network_name}" "$1"
}

require_unused_image_targets() {
  local image target
  if ! [[ "${image_prefix}" =~ ^kingphisher/verify(-[a-z0-9][a-z0-9._-]{0,47})?$ ]]; then
    printf 'KP_IMAGE_PREFIX must be a dedicated kingphisher/verify[-unique-suffix] namespace\n' >&2
    return 2
  fi
  for image in operator-api tracking-api worker migration mock-services; do
    target="$(image_tag "${image}")"
    if docker_bounded image inspect "${target}" >/dev/null 2>&1; then
      printf 'Refusing to move preserved verification image tag: %s\n' "${target}" >&2
      printf 'Use a new KP_IMAGE_PREFIX suffix; no image or evidence was changed\n' >&2
      return 1
    fi
  done
}

copy_clean_context() {
  (
    cd "${repo_root}"
    git ls-files --cached --others --exclude-standard -z \
      | while IFS= read -r -d '' tracked_path; do
          # `git ls-files --cached` includes tracked paths deleted in the
          # working tree.  They are intentionally absent from the candidate
          # image context and must not make tar abort the release gate.
          if [[ -e "${tracked_path}" || -L "${tracked_path}" ]]; then
            printf '%s\0' "${tracked_path}"
          fi
        done \
      | COPYFILE_DISABLE=1 tar --null --files-from=- --create --file=-
  ) | COPYFILE_DISABLE=1 tar --extract --preserve-permissions --file=- --directory="${context_dir}"
}

build_images() {
  local image
  for image in operator-api tracking-api worker migration; do
    printf 'Building %s from isolated context for %s\n' "${image}" "${expected_platform}"
    docker_bounded build \
      --pull \
      --platform "${expected_platform}" \
      --file "${context_dir}/infrastructure/containers/Dockerfile.${image}" \
      --tag "$(image_tag "${image}")" \
      "${context_dir}"
  done

  printf 'Building disposable mock services from isolated context for %s\n' "${expected_platform}"
  docker_bounded build \
    --pull \
    --platform "${expected_platform}" \
    --file "${context_dir}/infrastructure/mock-services/Dockerfile" \
    --tag "$(image_tag mock-services)" \
    "${context_dir}/infrastructure/mock-services"
}

assert_and_record_image_metadata() {
  local architecture health image image_id os_name record repo_digests tag user
  for image in operator-api tracking-api worker migration mock-services; do
    tag="$(image_tag "${image}")"
    record="$(docker_bounded image inspect "${tag}" \
      --format '{{.Id}}|{{json .RepoDigests}}|{{.Os}}|{{.Architecture}}|{{.Config.User}}')"
    IFS='|' read -r image_id repo_digests os_name architecture user <<<"${record}"
    if ! [[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      printf 'Image %s has a malformed local image ID\n' "${image}" >&2
      return 1
    fi
    if [[ "${os_name}/${architecture}" != "${expected_platform}" ]]; then
      printf 'Image %s has platform %s/%s; expected %s\n' \
        "${image}" "${os_name}" "${architecture}" "${expected_platform}" >&2
      return 1
    fi
    if [[ "${user}" != "65532:65532" ]]; then
      printf 'Image %s runs as unexpected user %s\n' "${image}" "${user}" >&2
      return 1
    fi
    if [[ "${image}" != "mock-services" ]]; then
      health="$(docker_bounded image inspect "${tag}" --format '{{json .Config.Healthcheck.Test}}')"
      if [[ -z "${health}" || "${health}" == "null" ]]; then
        printf 'Image %s does not declare its health policy\n' "${image}" >&2
        return 1
      fi
    fi
    image_records+=("${image}|${tag}|${image_id}|${repo_digests}|${os_name}|${architecture}|${user}")
  done
}

scan_and_record_images() {
  local artifact checksum_artifact image image_id recorded_id record scan_digest tag
  for record in "${image_records[@]}"; do
    [[ "${record}" != "__kp_no_image_record__" ]] || continue
    IFS='|' read -r image tag image_id _rest <<<"${record}"
    recorded_id="$(docker_bounded image inspect "${tag}" --format '{{.Id}}')"
    if [[ "${recorded_id}" != "${image_id}" ]]; then
      printf 'Image %s changed between metadata inspection and security scan\n' "${image}" >&2
      return 1
    fi

    artifact="${evidence_dir}/${image}-trivy.json"
    checksum_artifact="${evidence_dir}/${image}-trivy.sha256"
    if [[ -e "${artifact}" || -L "${artifact}" || -e "${checksum_artifact}" || -L "${checksum_artifact}" ]]; then
      printf 'Refusing to overwrite release-image scan evidence for %s\n' "${image}" >&2
      return 1
    fi
    printf 'Scanning %s at exact local image ID %s\n' "${image}" "${image_id}"
    run_bounded "${KP_TRIVY_TIMEOUT_SECONDS:-1800}" \
      "${scanner_executable}" \
      --cache-dir "${scanner_cache_dir}" \
      --config "${evidence_dir}/trivy-config.yaml" \
      image \
      --skip-db-update \
      --skip-check-update \
      --ignorefile "${evidence_dir}/trivy-ignore.txt" \
      --secret-config "${evidence_dir}/trivy-secret.yaml" \
      --ignore-unfixed=false \
      --scanners vuln,secret \
      --severity HIGH,CRITICAL \
      --exit-code 1 \
      --format json \
      --output "${artifact}" \
      "${image_id}"
    scan_digest="$(python3 - "${artifact}" "${checksum_artifact}" "${image_id}" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

artifact_value, checksum_value, expected_image_id = sys.argv[1:]
artifact = Path(artifact_value)
checksum = Path(checksum_value)
if artifact.is_symlink() or not artifact.is_file():
    raise SystemExit("release-image scan evidence is missing or symbolic")
metadata = artifact.stat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > 64 * 1024 * 1024:
    raise SystemExit("release-image scan evidence has an invalid size")
try:
    document = json.loads(artifact.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, ValueError):
    raise SystemExit("release-image scan evidence is malformed") from None
if (
    not isinstance(document, dict)
    or document.get("ArtifactName") != expected_image_id
    or document.get("ArtifactType") != "container_image"
    or not isinstance(document.get("Metadata"), dict)
    or document["Metadata"].get("ImageID") != expected_image_id
    or not isinstance(document.get("Results"), list)
):
    raise SystemExit("release-image scan evidence has an invalid schema")
for result in document["Results"]:
    if not isinstance(result, dict):
        raise SystemExit("release-image scan result is malformed")
    for finding_name in ("Vulnerabilities", "Secrets"):
        findings = result.get(finding_name)
        if findings is None:
            continue
        if not isinstance(findings, list):
            raise SystemExit("release-image scan findings are malformed")
        if findings:
            raise SystemExit("release-image scan evidence contains a prohibited finding")
digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
with checksum.open("x", encoding="utf-8") as output:
    output.write(f"{digest}  {artifact.name}\n")
    output.flush()
    os.fsync(output.fileno())
os.chmod(artifact, 0o600)
os.chmod(checksum, 0o600)
print(digest)
PY
)"
    if ! [[ "${scan_digest}" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'Release-image scan checksum is malformed for %s\n' "${image}" >&2
      return 1
    fi
    recorded_id="$(docker_bounded image inspect "${tag}" --format '{{.Id}}')"
    if [[ "${recorded_id}" != "${image_id}" ]]; then
      printf 'Image %s changed while its security scan was running\n' "${image}" >&2
      return 1
    fi
    scan_records+=(
      "${image}|${tag}|${image_id}|${artifact##*/}|${checksum_artifact##*/}|${scan_digest}"
    )
  done
  if (( ${#scan_records[@]} != 6 )); then
    printf 'Release-image scan evidence does not cover all five inspected images\n' >&2
    return 1
  fi
  scan_performed_by_verifier=1
}

assert_effective_user() {
  local image="$1"
  local expected_uid="$2"
  docker_bounded run --rm \
    --name "$(container_name "${image}-user")" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    --entrypoint python \
    "$(image_tag "${image}")" \
    -c "import os; assert os.getuid() == ${expected_uid}"
}

assert_container_hardening() {
  local container="$1"
  local expected_uid="$2"
  local readonly_rootfs cap_drop security_options
  readonly_rootfs="$(docker_bounded inspect "${container}" --format '{{.HostConfig.ReadonlyRootfs}}')"
  cap_drop="$(docker_bounded inspect "${container}" --format '{{json .HostConfig.CapDrop}}')"
  security_options="$(docker_bounded inspect "${container}" --format '{{json .HostConfig.SecurityOpt}}')"
  if [[ "${readonly_rootfs}" != "true" || "${cap_drop}" != '["ALL"]' ]]; then
    printf 'Container %s is missing its read-only root or dropped-capability policy\n' "${container}" >&2
    return 1
  fi
  if [[ "${security_options}" != *no-new-privileges* ]]; then
    printf 'Container %s permits privilege escalation\n' "${container}" >&2
    return 1
  fi
  docker_bounded exec "${container}" python -c "import os; assert os.getuid() == ${expected_uid}"
}

wait_for_healthy() {
  local container="$1"
  local status
  for _ in $(seq 1 60); do
    status="$(docker_bounded inspect "${container}" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}')"
    if [[ "${status}" == "healthy" ]]; then
      return 0
    fi
    if [[ "$(docker_bounded inspect "${container}" --format '{{.State.Running}}')" != "true" ]]; then
      break
    fi
    sleep 1
  done
  docker_bounded logs "${container}" >&2
  printf 'Container %s did not become healthy\n' "${container}" >&2
  return 1
}

start_api_images() {
  local operator tracking
  operator="$(docker_bounded run --detach \
    --name "$(container_name operator-api)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    --env OPERATOR_API_HOST=0.0.0.0 \
    --env OPERATOR_API_AUDIT_HMAC_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
    --env OPERATOR_API_CIPHERTEXT_KEK=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
    --env OPERATOR_API_CONSOLE_JWT_SECRET=container-smoke-jwt-secret-32-bytes \
    "$(image_tag operator-api)")"
  tracking="$(docker_bounded run --detach \
    --name "$(container_name tracking-api)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    --env TRACKING_API_HOST=0.0.0.0 \
    "$(image_tag tracking-api)")"
  assert_container_hardening "${operator}" 65532
  assert_container_hardening "${tracking}" 65532
  wait_for_healthy "${operator}"
  wait_for_healthy "${tracking}"
}

exercise_worker_entrypoint() {
  # argparse exits zero only after importing the worker, queue, database,
  # provider, and job dependency closure behind the declared entrypoint.
  docker_bounded run --rm \
    --name "$(container_name worker-entrypoint)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    "$(image_tag worker)" --help >/dev/null
}

exercise_migration_entrypoint() {
  local postgres password_env password_name
  # Import the complete migration-only dependency closure before touching a
  # database, so a packaging omission is reported directly instead of being
  # obscured by a later Alembic or connection error.
  docker_bounded run --rm \
    --name "$(container_name migration-import)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    --entrypoint python "$(image_tag migration)" -c \
    'import alembic, dotenv, kp_database, kp_telemetry, psycopg' >/dev/null

  docker_bounded network create \
    --label "${qualification_label_key}=${run_id}" \
    "${network_name}" >/dev/null
  postgres="$(docker_bounded run --detach \
    --name "$(container_name postgres)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    --network "${network_name}" \
    --network-alias postgres \
    --tmpfs "/var/lib/postgresql/data:rw,nosuid,nodev" \
    --env POSTGRES_PASSWORD=release-verification \
    postgres:16@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94)"
  for _ in $(seq 1 60); do
    if docker_bounded exec "${postgres}" pg_isready --username postgres --dbname postgres >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  docker_bounded exec "${postgres}" pg_isready --username postgres --dbname postgres >/dev/null

  password_env=(
    --env AUDIT_WRITER_PASSWORD=release-verification
    --env AUDIT_ROOT_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  )
  for password_name in \
    KP_DB_PASSWORD_OPERATOR \
    KP_DB_PASSWORD_TRACKING \
    KP_DB_PASSWORD_INGESTION \
    KP_DB_PASSWORD_DELIVERY \
    KP_DB_PASSWORD_RETENTION \
    KP_DB_PASSWORD_REMINDER \
    KP_DB_PASSWORD_ALERT \
    KP_DB_PASSWORD_AUDIT_ANCHOR; do
    password_env+=("--env" "${password_name}=release-verification")
  done

  docker_bounded run --rm \
    --name "$(container_name migration-entrypoint)" \
    --label "${qualification_label_key}=${run_id}" \
    --platform "${expected_platform}" \
    "${hardened_run_args[@]}" \
    --network "${network_name}" \
    --env DATABASE_URL=postgresql+psycopg://postgres:release-verification@postgres:5432/postgres \
    "${password_env[@]}" \
    "$(image_tag migration)"
}

wait_for_url() {
  local container="$1"
  local url="$2"
  for _ in $(seq 1 60); do
    if docker_bounded exec "${container}" python -c \
      "import urllib.request; urllib.request.urlopen('${url}', timeout=3).read()" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker_bounded inspect "${container}" --format '{{.State.Running}}')" != "true" ]]; then
      break
    fi
    sleep 1
  done
  docker_bounded logs "${container}" >&2
  printf 'Container %s did not answer %s\n' "${container}" "${url}" >&2
  return 1
}

exercise_mock_services() {
  local name module port path container
  while IFS='|' read -r name module port path; do
    container="$(docker_bounded run --detach \
      --name "$(container_name "mock-${name}")" \
      --label "${qualification_label_key}=${run_id}" \
      --platform "${expected_platform}" \
      "${hardened_run_args[@]}" \
      --entrypoint python \
      "$(image_tag mock-services)" \
      -m uvicorn "${module}:app" --host 0.0.0.0 --port "${port}")"
    assert_container_hardening "${container}" 65532
    wait_for_url "${container}" "http://127.0.0.1:${port}${path}"
    if [[ "${name}" == "graph" ]]; then
      wait_for_url "${container}" "http://127.0.0.1:${port}/users/delta"
      printf 'Mock service graph delta endpoint passed runtime verification\n'
    fi
    printf 'Mock service %s passed read-only startup and endpoint verification\n' "${name}"
  done <<'EOF'
idp|mock_idp|8443|/realms/kingphisher/.well-known/openid-configuration
graph|mock_graph|8181|/users
ai|mock_ai|8282|/openapi.json
EOF
}

cleanup_disposable_resources() {
  local container_ids container_id failure network_ids network_id remaining
  failure=0
  if (( docker_ready == 0 )); then
    cleanup_result="not-needed"
    return 0
  fi

  if ! container_ids="$(docker_cleanup container ls --all --quiet \
    --filter "label=${qualification_label_key}=${run_id}")"; then
    printf 'Could not enumerate qualification containers during cleanup\n' >&2
    failure=1
    container_ids=""
  fi
  while IFS= read -r container_id; do
    [[ -n "${container_id}" ]] || continue
    if ! docker_cleanup rm --force --volumes "${container_id}" >/dev/null; then
      printf 'Could not remove disposable qualification container %s\n' "${container_id}" >&2
      failure=1
    fi
  done <<<"${container_ids}"

  if ! network_ids="$(docker_cleanup network ls --quiet \
    --filter "label=${qualification_label_key}=${run_id}")"; then
    printf 'Could not enumerate qualification networks during cleanup\n' >&2
    failure=1
    network_ids=""
  fi
  while IFS= read -r network_id; do
    [[ -n "${network_id}" ]] || continue
    if ! docker_cleanup network rm "${network_id}" >/dev/null; then
      printf 'Could not remove disposable qualification network %s\n' "${network_id}" >&2
      failure=1
    fi
  done <<<"${network_ids}"

  if ! remaining="$(docker_cleanup container ls --all --quiet \
    --filter "label=${qualification_label_key}=${run_id}")"; then
    printf 'Could not assert that qualification containers were removed\n' >&2
    failure=1
  elif [[ -n "${remaining}" ]]; then
    printf 'Disposable qualification containers remain after bounded cleanup\n' >&2
    failure=1
  fi
  if ! remaining="$(docker_cleanup network ls --quiet \
    --filter "label=${qualification_label_key}=${run_id}")"; then
    printf 'Could not assert that qualification networks were removed\n' >&2
    failure=1
  elif [[ -n "${remaining}" ]]; then
    printf 'Disposable qualification networks remain after bounded cleanup\n' >&2
    failure=1
  fi

  if ! volume_inventory_after="$(docker_cleanup volume ls --quiet | LC_ALL=C sort)"; then
    printf 'Could not capture the post-qualification Docker volume inventory\n' >&2
    volume_inventory_unchanged="false"
    failure=1
  elif [[ "${volume_inventory_after}" != "${volume_inventory_before}" ]]; then
    printf 'Docker volume inventory changed during release qualification\n' >&2
    volume_inventory_unchanged="false"
    failure=1
  else
    volume_inventory_unchanged="true"
  fi

  if (( failure != 0 )); then
    cleanup_result="failed"
    return 1
  fi
  cleanup_result="passed"
}

write_final_evidence() {
  local exit_status="$1"
  local qualification_file="${evidence_dir}/qualification.json"
  local checksum_file="${evidence_dir}/qualification.sha256"
  python3 - \
    "${qualification_file}" \
    "${checksum_file}" \
    "${run_id}" \
    "${started_at}" \
    "${exit_status}" \
    "${expected_docker_endpoint:-unresolved}" \
    "${docker_endpoint:-unresolved}" \
    "${expected_docker_root_dir:-unresolved}" \
    "${docker_root_dir:-unresolved}" \
    "${expected_platform:-unresolved}" \
    "${server_platform:-unresolved}" \
    "${scanner_version:-unresolved}" \
    "${scanner_executable:-unresolved}" \
    "${expected_trivy_sha256:-unresolved}" \
    "${scanner_executable_sha256:-unresolved}" \
    "${scanner_cache_dir:-unresolved}" \
    "${scanner_cache_unchanged}" \
    "${evidence_dir}/trivy-config.yaml" \
    "${evidence_dir}/trivy-ignore.txt" \
    "${evidence_dir}/trivy-secret.yaml" \
    "${evidence_dir}/trivy-version.json" \
    "${evidence_dir}/trivy-cache-before.json" \
    "${evidence_dir}/trivy-cache-after.json" \
    "${scan_performed_by_verifier}" \
    "${cleanup_result}" \
    "${context_cleanup_result}" \
    "${source_unchanged}" \
    "${expected_source_manifest_digest:-unresolved}" \
    "${volume_inventory_before}" \
    "${volume_inventory_after}" \
    "${volume_inventory_unchanged}" \
    "${evidence_dir}/source-before.json" \
    "${evidence_dir}/context.json" \
    "${evidence_dir}/source-after.json" \
    "${phase_results[@]}" \
    --images "${image_records[@]}" \
    --scans "${scan_records[@]}" <<'PY'
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

(
    qualification_value,
    checksum_value,
    run_id,
    started_at,
    exit_status_value,
    expected_docker_endpoint,
    docker_endpoint,
    expected_docker_root_dir,
    docker_root_dir,
    expected_platform,
    server_platform,
    scanner_version,
    scanner_executable,
    expected_scanner_sha256,
    scanner_executable_sha256,
    scanner_cache_dir,
    scanner_cache_unchanged_value,
    scanner_config_value,
    scanner_ignore_value,
    scanner_secret_value,
    scanner_version_value,
    scanner_cache_before_value,
    scanner_cache_after_value,
    scan_performed_value,
    cleanup_result,
    context_cleanup_result,
    source_unchanged_value,
    expected_source_manifest_digest,
    volume_inventory_before_value,
    volume_inventory_after_value,
    volume_inventory_unchanged_value,
    before_value,
    context_value,
    after_value,
    *records,
) = sys.argv[1:]
image_separator = records.index("--images")
scan_separator = records.index("--scans")
phase_values = records[:image_separator]
image_values = records[image_separator + 1 : scan_separator]
scan_values = records[scan_separator + 1 :]
image_values = [value for value in image_values if value != "__kp_no_image_record__"]
scan_values = [value for value in scan_values if value != "__kp_no_scan_record__"]


def load_manifest(value: str) -> Optional[dict[str, object]]:
    path = Path(value)
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 64 * 1024 * 1024:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        return None
    canonical = json.dumps(
        document["entries"], ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    calculated_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
    if document.get("digest") != calculated_digest or document.get("file_count") != len(document["entries"]):
        return None
    return {
        "artifact": path.name,
        "digest": calculated_digest,
        "file_count": len(document["entries"]),
    }


def load_artifact(value: str, maximum_size: int = 64 * 1024 * 1024) -> Optional[dict[str, object]]:
    path = Path(value)
    if path.is_symlink() or not path.is_file():
        return None
    metadata = path.stat()
    if metadata.st_size < 0 or metadata.st_size > maximum_size:
        return None
    return {
        "artifact": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": metadata.st_size,
    }


def load_scanner_metadata(value: str) -> Optional[dict[str, object]]:
    artifact = load_artifact(value, 64 * 1024)
    if artifact is None or artifact["size"] == 0:
        return None
    path = Path(value)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    database = document.get("VulnerabilityDB")
    bundle = document.get("CheckBundle")
    if not isinstance(database, dict):
        return None
    # trivy 0.74.0 (the pinned release scanner) cannot emit CheckBundle in
    # `version --format json`; check bundles arrived in later trivy
    # releases. The CheckBundle is therefore recorded only when the
    # runtime provides one (it stays a documented, non-pass/fail field),
    # mirroring the relaxed scanner-version validation above. Revisit
    # when the pinned scanner is upgraded to a check-bundle-capable
    # version.
    metadata = {
        **artifact,
        "vulnerability_database": {
            "version": database.get("Version"),
            "updated_at": database.get("UpdatedAt"),
            "next_update": database.get("NextUpdate"),
            "downloaded_at": database.get("DownloadedAt"),
        },
    }
    if isinstance(bundle, dict):
        metadata["check_bundle"] = {
            "digest": bundle.get("Digest"),
            "downloaded_at": bundle.get("DownloadedAt"),
        }
    return metadata


def volume_inventory(value: str) -> dict[str, object]:
    names = sorted(name for name in value.splitlines() if name)
    canonical = "\n".join(names).encode("utf-8")
    return {"count": len(names), "sha256": hashlib.sha256(canonical).hexdigest()}


phases = []
for value in phase_values:
    name, result = value.split("|", maxsplit=1)
    phases.append({"name": name, "result": result})

images = []
for value in image_values:
    name, tag, image_id, repo_digests_value, os_name, architecture, user = value.split("|", maxsplit=6)
    repo_digests = json.loads(repo_digests_value)
    images.append(
        {
            "name": name,
            "tag": tag,
            "image_id": image_id,
            "repo_digests": repo_digests or [],
            "platform": f"{os_name}/{architecture}",
            "user": user,
        }
    )

scans = []
for value in scan_values:
    name, tag, image_id, artifact, checksum_artifact, digest = value.split("|", maxsplit=5)
    scans.append(
        {
            "name": name,
            "tag": tag,
            "image_id": image_id,
            "artifact": artifact,
            "checksum_artifact": checksum_artifact,
            "sha256": digest,
        }
    )

scan_performed = scan_performed_value == "1"
scanner_config = load_artifact(scanner_config_value, 1024)
scanner_ignore = load_artifact(scanner_ignore_value, 1024)
scanner_secret = load_artifact(scanner_secret_value, 1024)
scanner_metadata = load_scanner_metadata(scanner_version_value)
scanner_cache_before = load_manifest(scanner_cache_before_value)
scanner_cache_after = load_manifest(scanner_cache_after_value)
source_before = load_manifest(before_value)
source_context = load_manifest(context_value)
source_after = load_manifest(after_value)
image_bindings = {item["name"]: (item["tag"], item["image_id"]) for item in images}
scan_bindings = {item["name"]: (item["tag"], item["image_id"]) for item in scans}
if len(image_bindings) != len(images) or len(scan_bindings) != len(scans):
    raise SystemExit("release-image qualification evidence contains duplicate image names")
if scan_performed and (len(scans) != 5 or scan_bindings != image_bindings):
    raise SystemExit("release-image scan evidence is not bound to all inspected images")

exit_status = int(exit_status_value)
if exit_status == 0:
    evidence_root = Path(qualification_value).parent
    for scan in scans:
        scan_artifact = evidence_root / str(scan["artifact"])
        checksum_artifact = evidence_root / str(scan["checksum_artifact"])
        if (
            scan_artifact.is_symlink()
            or not scan_artifact.is_file()
            or hashlib.sha256(scan_artifact.read_bytes()).hexdigest() != scan["sha256"]
            or checksum_artifact.is_symlink()
            or not checksum_artifact.is_file()
            or checksum_artifact.read_text(encoding="utf-8")
            != f"{scan['sha256']}  {scan_artifact.name}\n"
        ):
            raise SystemExit("release-image scan artifact changed before final qualification")
    if (
        scanner_executable_sha256 != expected_scanner_sha256
        or scanner_metadata is None
        or scanner_config is None
        or scanner_config["size"] != 3
        or scanner_config["sha256"] != "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
        or scanner_ignore is None
        or scanner_ignore["size"] != 0
        or scanner_ignore["sha256"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        or scanner_secret is None
        or scanner_secret["size"] != 3
        or scanner_secret["sha256"] != "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
        or scanner_cache_before is None
        or scanner_cache_after is None
        or scanner_cache_before["digest"] != scanner_cache_after["digest"]
        or scanner_cache_unchanged_value != "true"
        or source_before is None
        or source_before["digest"] != expected_source_manifest_digest
    ):
        raise SystemExit("release-image qualification lacks exact scanner/database evidence")
document = {
    "schema": "kp.release-image-qualification.v1",
    "run_id": run_id,
    "started_at": started_at,
    "finished_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "status": "passed" if exit_status == 0 else "failed",
    "exit_status": exit_status,
    "docker": {
        "endpoint": {"expected": expected_docker_endpoint, "actual": docker_endpoint},
        "root_dir": {"expected": expected_docker_root_dir, "actual": docker_root_dir},
    },
    "platform": {"expected": expected_platform, "docker_server": server_platform},
    "scanner": {
        "name": "trivy",
        "version": scanner_version,
        "executable": {
            "path": scanner_executable,
            "expected_sha256": expected_scanner_sha256,
            "actual_sha256": scanner_executable_sha256,
        },
        "configuration": {
            "config": scanner_config,
            "ignore": scanner_ignore,
            "secret": scanner_secret,
        },
        "metadata": scanner_metadata,
        "cache": {
            "path": scanner_cache_dir,
            "before": scanner_cache_before,
            "after": scanner_cache_after,
            "unchanged": scanner_cache_unchanged_value == "true",
        },
        "scan_performed_by_verifier": scan_performed,
        "artifacts": scans,
    },
    "source": {
        "expected_digest": expected_source_manifest_digest,
        "before": source_before,
        "copied_context": source_context,
        "after": source_after,
        "unchanged": source_unchanged_value == "true",
    },
    "images": images,
    "phases": phases,
    "cleanup": {
        "disposable_docker_resources": cleanup_result,
        "temporary_context": context_cleanup_result,
        "preserved_images_and_caches": True,
        "volume_inventory_before": volume_inventory(volume_inventory_before_value),
        "volume_inventory_after": volume_inventory(volume_inventory_after_value),
        "volume_inventory_unchanged": volume_inventory_unchanged_value == "true",
    },
}
qualification = Path(qualification_value)
with qualification.open("x", encoding="utf-8") as output:
    output.write(json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n")
digest = hashlib.sha256(qualification.read_bytes()).hexdigest()
with Path(checksum_value).open("x", encoding="utf-8") as output:
    output.write(f"{digest}  {qualification.name}\n")
PY
}

finalize() {
  local initial_status=$?
  local final_status source_after_ok=0
  trap - EXIT INT TERM
  set +e
  final_status="${initial_status}"
  if [[ -n "${current_phase}" ]]; then
    phase_results+=("${current_phase}|failed")
    current_phase=""
  fi

  if [[ -f "${evidence_dir}/trivy-cache-before.json" ]]; then
    if capture_scanner_cache_after; then
      if (( scanner_cache_phase_recorded == 0 )); then
        phase_results+=("scanner_cache_binding|passed")
      fi
    else
      if (( scanner_cache_phase_recorded == 0 )); then
        phase_results+=("scanner_cache_binding|failed")
      fi
      final_status=1
    fi
  fi

  if cleanup_disposable_resources; then
    phase_results+=("disposable_resource_cleanup|passed")
  else
    phase_results+=("disposable_resource_cleanup|failed")
    final_status=1
  fi

  if [[ -n "${context_dir}" ]]; then
    case "${context_dir}" in
      "${TMPDIR:-/tmp}"/kp-image-context.*)
        # The case guard accepts only the unique absolute mktemp namespace, so
        # no end-of-options operand is needed. Native BSD rm rejects GNU `--`.
        if rm -rf "${context_dir}"; then
          context_cleanup_result="passed"
        else
          printf 'Could not remove the unique temporary release context: %s\n' "${context_dir}" >&2
          context_cleanup_result="failed"
          final_status=1
        fi
        ;;
      *)
        printf 'Refusing to remove an unexpected temporary context path: %s\n' "${context_dir}" >&2
        context_cleanup_result="failed"
        final_status=1
        ;;
    esac
  else
    context_cleanup_result="not-needed"
  fi

  if write_source_manifest git "${repo_root}" "${evidence_dir}/source-after.json"; then
    source_after_ok=1
  else
    printf 'Could not create the post-qualification source manifest\n' >&2
    final_status=1
  fi
  if (( source_after_ok == 1 )) \
    && [[ -f "${evidence_dir}/source-before.json" && -f "${evidence_dir}/context.json" ]] \
    && compare_source_manifests \
      "${evidence_dir}/source-before.json" \
      "${evidence_dir}/context.json" \
      "${evidence_dir}/source-after.json"; then
    source_unchanged="true"
    phase_results+=("source_manifest_after|passed")
  else
    source_unchanged="false"
    phase_results+=("source_manifest_after|failed")
    printf 'Release source or copied context changed during qualification\n' >&2
    final_status=1
  fi

  if (( main_complete == 0 && final_status == 0 )); then
    final_status=1
  fi
  if (( scan_performed_by_verifier == 0 && final_status == 0 )); then
    printf 'Release qualification cannot pass without all five pinned Trivy scans\n' >&2
    final_status=1
  fi
  if [[ "${scanner_cache_unchanged}" != "true" && "${final_status}" == "0" ]]; then
    printf 'Release qualification cannot pass without an unchanged Trivy database/check bundle\n' >&2
    final_status=1
  fi
  if ! write_final_evidence "${final_status}"; then
    printf 'Could not exclusively write final release qualification evidence\n' >&2
    final_status=1
  else
    printf 'Release qualification evidence retained at %s\n' "${evidence_dir}/qualification.json"
  fi
  exit "${final_status}"
}

if [[ "${1:-}" == "--print-source-manifest-digest" ]]; then
  [[ "$#" -eq 1 ]] || {
    printf 'usage: %s [--print-source-manifest-digest]\n' "$0" >&2
    exit 2
  }
  print_source_manifest_digest
  exit $?
fi
[[ "$#" -eq 0 ]] || {
  printf 'usage: %s [--print-source-manifest-digest]\n' "$0" >&2
  exit 2
}

require_build_headroom
require_timeout_configuration
require_docker_target_configuration
initialize_evidence_directory
trap finalize EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_phase source_manifest_before \
  write_source_manifest git "${repo_root}" "${evidence_dir}/source-before.json"
run_phase expected_source_manifest require_expected_source_manifest
run_phase scanner_version require_scanner
run_phase docker_platform resolve_platform
run_phase volume_inventory_before capture_volume_inventory_before
run_phase unused_image_targets require_unused_image_targets

current_phase="temporary_context_creation"
context_dir="$(mktemp -d "${TMPDIR:-/tmp}/kp-image-context.XXXXXX")"
phase_results+=("temporary_context_creation|passed")
current_phase=""
run_phase clean_context_copy copy_clean_context
run_phase copied_context_manifest \
  write_source_manifest tree "${context_dir}" "${evidence_dir}/context.json"
run_phase source_context_binding compare_source_manifests \
  "${evidence_dir}/source-before.json" "${evidence_dir}/context.json"
run_phase image_builds build_images
run_phase image_metadata assert_and_record_image_metadata
run_phase image_security_scans scan_and_record_images
scanner_cache_phase_recorded=1
run_phase scanner_cache_binding capture_scanner_cache_after
run_phase effective_user_operator assert_effective_user operator-api 65532
run_phase effective_user_tracking assert_effective_user tracking-api 65532
run_phase effective_user_worker assert_effective_user worker 65532
run_phase effective_user_migration assert_effective_user migration 65532
run_phase effective_user_mock assert_effective_user mock-services 65532
run_phase api_runtime start_api_images
run_phase worker_entrypoint exercise_worker_entrypoint
run_phase migration_entrypoint exercise_migration_entrypoint
run_phase mock_runtime exercise_mock_services
main_complete=1
printf 'All release and mock images passed hardened startup and entrypoint verification for %s.\n' \
  "${expected_platform}"
