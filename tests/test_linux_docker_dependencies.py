"""Run the real installer dependency phase with task-owned command doubles.

No real package manager, Docker engine, project environment or lifecycle script
is called. Reaching the recovery boundary is an intentional test exit91.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or "/bin/bash"


def executable(path: Path, body: str) -> None:
    path.write_text("#!/bin/bash\nset -eu\n" + body)
    path.chmod(0o700)


def installer(
    tmp_path: Path,
    *,
    candidates: str = "",
    installed: str = "",
    daemon_ready: bool = True,
    compose_ready: bool = False,
    broken_install: bool = False,
    skip_deps: bool = False,
    endpoint: str = "unix:///var/run/docker.sock",
    docker_host: str = "",
    docker_context: str = "",
    reject_package_removal: bool = False,
) -> tuple[subprocess.CompletedProcess[str], str]:
    project, binary = tmp_path / "project", tmp_path / "bin"
    scripts = project / "scripts"
    scripts.mkdir(parents=True)
    binary.mkdir()
    # Keep a real host's dockerd/package tools out of the simulated clean host.
    for name in ("dirname", "awk", "git", "curl", "openssl", "touch", "grep", "sleep"):
        command = shutil.which(name)
        assert command is not None
        (binary / name).symlink_to(command)
    for name in ("install.sh", "linux-docker-packages.sh"):
        shutil.copyfile(ROOT / "scripts" / name, scripts / name)
    (scripts / "bootstrap_env.sh").write_text(
        'bounded() { shift; "$@"; }\n'
        "bounded_seconds_are_valid() { return 0; }\n"
        "bootstrap_docker_host() { return 0; }\n"
        '_validate_recovery_configuration_before_bootstrap() { echo recovery-boundary >> "$TRACE"; exit 91; }\n'
    )
    executable(binary / "uname", "echo Linux\n")
    executable(binary / "id", 'if [ "${1:-}" = -u ]; then echo 0; else echo qualifier; fi\n')
    executable(
        binary / "df",
        "printf 'Filesystem 1024-blocks Used Available Capacity Mounted\\n/dev/task 99999999 1 99999998 1%% /\\n'\n",
    )
    executable(
        binary / "uv",
        'if [ "$1" = --version ]; then echo "uv 0.11.0"; else echo UNEXPECTED-UV >> "$TRACE"; exit 92; fi\n',
    )
    executable(
        binary / "docker",
        """
echo "docker $*" >> "$TRACE"
case "$*" in
  info) [ "$DAEMON_READY" = 1 ] || [ -e "$STATE/daemon" ] ;;
  "compose version") [ "$COMPOSE_READY" = 1 ] || [ -e "$STATE/compose" ] ;;
  "context inspect"*) printf '%s\\n' "$ENDPOINT" ;;
  version*) exit 0 ;;
  *) echo UNEXPECTED-LIFECYCLE >> "$TRACE"; exit 93 ;;
esac
""",
    )
    executable(
        binary / "apt-cache",
        """
echo "apt-cache $*" >> "$TRACE"
case " $CANDIDATES " in
  *" $2 "*) printf '%s\\n  Candidate: 2.27.0-1\\n' "$2" ;;
  *) printf '%s\\n  Candidate: (none)\\n' "$2" ;;
esac
""",
    )
    executable(
        binary / "dpkg-query",
        """
package="${@: -1}"
echo "dpkg-query $package" >> "$TRACE"
case " $INSTALLED " in
  *" $package "*) printf 'install ok installed'; exit 0 ;;
  *) exit 1 ;;
esac
""",
    )
    executable(
        binary / "apt-get",
        """
echo "apt-get $*" >> "$TRACE"
if [ "$1" = --no-remove ]; then
  [ "$REJECT_PACKAGE_REMOVAL" = 0 ] || exit 100
  [ "$BROKEN_INSTALL" != 0 ] || touch "$STATE/compose"
fi
""",
    )
    executable(binary / "systemctl", 'echo "systemctl $*" >> "$TRACE"; touch "$STATE/daemon"\n')
    trace = tmp_path / "trace"
    environment = {
        **os.environ,
        "PATH": str(binary),
        "TRACE": str(trace),
        "STATE": str(tmp_path),
        "USER": "qualifier",
        "CANDIDATES": candidates,
        "INSTALLED": installed,
        "DAEMON_READY": str(int(daemon_ready)),
        "COMPOSE_READY": str(int(compose_ready)),
        "BROKEN_INSTALL": str(int(broken_install)),
        "ENDPOINT": endpoint,
        "DOCKER_HOST": docker_host,
        "DOCKER_CONTEXT": docker_context,
        "REJECT_PACKAGE_REMOVAL": str(int(reject_package_removal)),
    }
    result = subprocess.run(  # noqa: S603 - fixed installer and task-owned PATH command doubles
        [BASH, str(scripts / "install.sh"), *(["--skip-deps"] if skip_deps else [])],
        cwd=project,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    return result, trace.read_text() if trace.exists() else ""


@pytest.mark.parametrize("package", ["docker-compose-v2", "docker-compose-plugin"])
def test_available_distribution_or_upstream_compose_package_repairs_missing_plugin(tmp_path, package):
    result, trace = installer(tmp_path, candidates=package)
    assert result.returncode == 91, result.stderr
    assert f"apt-get --no-remove install -y {package}\n" in trace
    assert "docker.io" not in trace  # healthy daemon provider is preserved
    assert "recovery-boundary" in trace
    assert trace.index("apt-get update") < trace.index("apt-cache policy") < trace.index("apt-get --no-remove install")
    assert "UNEXPECTED" not in trace


def test_plugin_candidate_is_preferred_when_both_providers_are_available(tmp_path):
    result, trace = installer(tmp_path, candidates="docker-compose-v2 docker-compose-plugin")
    assert result.returncode == 91
    assert "apt-get --no-remove install -y docker-compose-plugin\n" in trace


def test_already_installed_provider_is_preserved_before_an_alternative_candidate(tmp_path):
    result, trace = installer(tmp_path, candidates="docker-compose-plugin", installed="docker-compose-v2")
    assert result.returncode == 91
    assert "apt-get --no-remove install -y docker-compose-v2\n" in trace
    assert "apt-cache policy" not in trace


def test_no_configured_candidate_fails_actionably_before_install_or_lifecycle(tmp_path):
    result, trace = installer(tmp_path)
    assert result.returncode == 1
    assert "unavailable in the configured apt sources" in result.stderr
    assert "No repositories were added" in result.stderr
    assert "apt-get update" in trace and "apt-get --no-remove install" not in trace
    assert "recovery-boundary" not in trace and "UNEXPECTED" not in trace


def test_cold_daemon_install_includes_engine_and_selected_compose(tmp_path):
    result, trace = installer(tmp_path, daemon_ready=False, candidates="docker-compose-v2")
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker.io docker-compose-v2\n" in trace
    assert "systemctl enable --now docker" in trace
    assert "recovery-boundary" in trace and "UNEXPECTED" not in trace


def test_skip_deps_missing_compose_fails_without_package_or_project_changes(tmp_path):
    result, trace = installer(tmp_path, skip_deps=True, candidates="docker-compose-v2")
    assert result.returncode == 1
    assert "Docker Compose v2 could not run" in result.stderr
    assert "re-run without --skip-deps" in result.stderr
    assert "apt-" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace and "UNEXPECTED" not in trace


def test_package_install_success_without_working_compose_fails_before_lifecycle(tmp_path):
    result, trace = installer(tmp_path, candidates="docker-compose-v2", broken_install=True)
    assert result.returncode == 1
    assert "Docker Compose v2 could not run" in result.stderr
    assert "apt-get --no-remove install -y docker-compose-v2" in trace
    assert "recovery-boundary" not in trace and "UNEXPECTED" not in trace


def test_working_daemon_and_compose_do_not_invoke_package_manager(tmp_path):
    result, trace = installer(tmp_path, compose_ready=True)
    assert result.returncode == 91
    assert "apt-" not in trace and "systemctl" not in trace
    assert "recovery-boundary" in trace


def test_stopped_existing_docker_ce_is_started_without_requesting_distro_engine(tmp_path):
    result, trace = installer(tmp_path, daemon_ready=False, installed="docker-ce", candidates="docker-compose-plugin")
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker-compose-plugin\n" in trace
    assert "install -y docker.io" not in trace
    assert "systemctl start docker" in trace
    assert "systemctl enable" not in trace


@pytest.mark.parametrize(
    "configuration",
    [
        {"docker_host": "ssh://qualified-host/reviewed/docker.sock"},
        {"docker_context": "reviewed-remote"},
        {"docker_host": "unix:///var/run/docker.sock", "docker_context": "kp-remote-mac"},
        {"docker_host": "unix:///var/run/docker.sock", "docker_context": "default", "endpoint": "tcp://remote:2376"},
        {"endpoint": "tcp://qualified-host:2376"},
        {"docker_host": "unix:///run/user/1000/docker.sock"},
        {"endpoint": ""},
    ],
)
def test_unavailable_or_ambiguous_configured_endpoint_never_falls_back_to_local_engine(tmp_path, configuration):
    result, trace = installer(tmp_path, daemon_ready=False, candidates="docker-compose-v2", **configuration)
    assert result.returncode == 1
    assert "configured Docker endpoint" in result.stderr
    assert "no local engine fallback" in result.stderr
    assert "apt-" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace and "UNEXPECTED" not in trace


def test_transitive_package_replacement_is_refused_before_service_or_project_changes(tmp_path):
    result, trace = installer(
        tmp_path, daemon_ready=False, installed="docker-ce", candidates="docker-compose-v2", reject_package_removal=True
    )
    assert result.returncode == 1
    assert "could not preserve installed packages" in result.stderr
    assert "--no-remove install" in trace
    assert "systemctl" not in trace and "recovery-boundary" not in trace
