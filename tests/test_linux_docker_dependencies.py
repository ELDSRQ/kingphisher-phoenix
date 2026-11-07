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
    buildx_ready: bool = True,
    broken_install: bool = False,
    broken_buildx_install: bool = False,
    fresh_group: bool = False,
    skip_deps: bool = False,
    endpoint: str = "unix:///var/run/docker.sock",
    docker_host: str = "",
    docker_context: str = "",
    reject_package_removal: bool = False,
    apt_plan: str | None = None,
    simulation_exit: int = 0,
    simulation_stderr: str = "",
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
    executable(
        binary / "id",
        """
if [ "${1:-}" = -u ]; then
  if [ "$FRESH_GROUP" = 1 ]; then echo 1000; else echo 0; fi
elif [ "${1:-}" = -nG ] && [ -e "$STATE/group" ]; then echo 'qualifier docker'
else echo qualifier
fi
""",
    )
    executable(binary / "sudo", 'exec "$@"\n')
    executable(binary / "usermod", 'echo "usermod $*" >> "$TRACE"; touch "$STATE/group"\n')
    executable(
        binary / "sg",
        """
echo "sg $*" >> "$TRACE"
[ "$1" = docker ] && [ "$2" = -c ]
export IN_DOCKER_GROUP=1
exec /bin/bash -c "$3"
""",
    )
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
  info)
    [ "$FRESH_GROUP" != 1 ] || [ "${IN_DOCKER_GROUP:-0}" = 1 ] || exit 1
    [ "$DAEMON_READY" = 1 ] || [ -e "$STATE/daemon" ] ;;
  "compose version") [ "$COMPOSE_READY" = 1 ] || [ -e "$STATE/compose" ] ;;
  "buildx version")
    [ "$FRESH_GROUP" != 1 ] || [ "${IN_DOCKER_GROUP:-0}" = 1 ] || exit 1
    [ "$BUILDX_READY" = 1 ] || [ -e "$STATE/buildx" ] ;;
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
if [ "$1" = --simulate ]; then
  echo "apt-plan-locale ${LC_ALL:-unset}" >> "$TRACE"
  [ -z "$SIMULATION_STDERR" ] || printf '%s\\n' "$SIMULATION_STDERR" >&2
  [ "$SIMULATION_EXIT" = 0 ] || exit "$SIMULATION_EXIT"
  if [ "$CUSTOM_APT_PLAN" = 1 ]; then
    printf '%s\\n' "$APT_PLAN"
  else
    count=0
    for package in "$@"; do
      case "$package" in
        docker-compose-v2|docker-compose-plugin|docker-buildx|docker-buildx-plugin) count=$((count+1)) ;;
      esac
    done
    printf 'Reading package lists... Done\\nBuilding dependency tree... Done\\nReading state information... Done\\n'
    printf '0 upgraded, %s newly installed, 0 to remove and 0 not upgraded.\\n' "$count"
    for package in "$@"; do
      case "$package" in
        docker-compose-v2|docker-compose-plugin|docker-buildx|docker-buildx-plugin)
          printf 'Inst %s (1.0 Ubuntu:24.04/noble [amd64])\\n' "$package"
          printf 'Conf %s (1.0 Ubuntu:24.04/noble [amd64])\\n' "$package" ;;
      esac
    done
  fi
  exit 0
fi
if [ "$1" = --no-remove ]; then
  [ "$REJECT_PACKAGE_REMOVAL" = 0 ] || exit 100
  for package in "$@"; do
    case "$package" in
      docker-compose-v2|docker-compose-plugin) [ "$BROKEN_INSTALL" != 0 ] || touch "$STATE/compose" ;;
      docker-buildx|docker-buildx-plugin) [ "$BROKEN_BUILDX_INSTALL" != 0 ] || touch "$STATE/buildx" ;;
    esac
  done
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
        "BUILDX_READY": str(int(buildx_ready)),
        "BROKEN_INSTALL": str(int(broken_install)),
        "BROKEN_BUILDX_INSTALL": str(int(broken_buildx_install)),
        "FRESH_GROUP": str(int(fresh_group)),
        "ENDPOINT": endpoint,
        "DOCKER_HOST": docker_host,
        "DOCKER_CONTEXT": docker_context,
        "REJECT_PACKAGE_REMOVAL": str(int(reject_package_removal)),
        "CUSTOM_APT_PLAN": str(int(apt_plan is not None)),
        "APT_PLAN": apt_plan or "",
        "SIMULATION_EXIT": str(simulation_exit),
        "SIMULATION_STDERR": simulation_stderr,
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


@pytest.mark.parametrize("package", ["docker-buildx", "docker-buildx-plugin"])
def test_missing_buildx_repairs_only_cli_on_working_engine(tmp_path, package):
    result, trace = installer(tmp_path, compose_ready=True, buildx_ready=False, candidates=package)
    assert result.returncode == 91, result.stderr
    assert f"apt-get --no-remove install -y {package}\n" in trace
    assert "docker.io" not in trace and "systemctl" not in trace
    assert "docker buildx version" in trace and "recovery-boundary" in trace
    assert "UNEXPECTED" not in trace


def test_cold_install_includes_buildx_before_recovery_or_project_lifecycle(tmp_path):
    result, trace = installer(
        tmp_path, daemon_ready=False, buildx_ready=False, candidates="docker-compose-v2 docker-buildx"
    )
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker.io docker-compose-v2 docker-buildx\n" in trace
    assert "docker buildx version" in trace
    assert trace.rindex("docker buildx version") < trace.index("recovery-boundary")


def test_skip_deps_missing_buildx_refuses_without_mutations(tmp_path):
    result, trace = installer(tmp_path, compose_ready=True, buildx_ready=False, skip_deps=True)
    assert result.returncode == 1
    assert "Docker Buildx could not run" in result.stderr
    assert "re-run without --skip-deps" in result.stderr
    assert "apt-" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace


def test_missing_buildx_without_trusted_candidate_refuses_before_install(tmp_path):
    result, trace = installer(tmp_path, compose_ready=True, buildx_ready=False)
    assert result.returncode == 1
    assert "Docker Buildx is unavailable in the configured apt sources" in result.stderr
    assert "No repositories were added" in result.stderr
    assert "apt-get update" in trace and "apt-get --no-remove install" not in trace
    assert "systemctl" not in trace and "recovery-boundary" not in trace


def test_buildx_installed_provider_precedes_alternative_candidate(tmp_path):
    result, trace = installer(
        tmp_path, compose_ready=True, buildx_ready=False, installed="docker-buildx", candidates="docker-buildx-plugin"
    )
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker-buildx\n" in trace
    assert "apt-cache policy" not in trace


def test_buildx_upstream_plugin_candidate_precedes_distro_candidate(tmp_path):
    result, trace = installer(
        tmp_path, compose_ready=True, buildx_ready=False, candidates="docker-buildx docker-buildx-plugin"
    )
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker-buildx-plugin\n" in trace


def test_buildx_install_success_without_working_plugin_refuses_before_lifecycle(tmp_path):
    result, trace = installer(
        tmp_path, compose_ready=True, buildx_ready=False, candidates="docker-buildx", broken_buildx_install=True
    )
    assert result.returncode == 1
    assert "Docker Buildx could not run" in result.stderr
    assert "apt-get --no-remove install -y docker-buildx\n" in trace
    assert "recovery-boundary" not in trace and "UNEXPECTED" not in trace


def test_buildx_repair_does_not_allow_package_replacement_or_service_changes(tmp_path):
    result, trace = installer(
        tmp_path, compose_ready=True, buildx_ready=False, candidates="docker-buildx", reject_package_removal=True
    )
    assert result.returncode == 1
    assert "could not preserve installed packages" in result.stderr
    assert "apt-get --no-remove install -y docker-buildx\n" in trace
    assert "systemctl" not in trace and "recovery-boundary" not in trace


def test_stopped_existing_engine_buildx_repair_preserves_provider(tmp_path):
    result, trace = installer(
        tmp_path,
        daemon_ready=False,
        compose_ready=True,
        buildx_ready=False,
        installed="docker-ce",
        candidates="docker-buildx-plugin",
    )
    assert result.returncode == 91, result.stderr
    assert "apt-get --no-remove install -y docker-buildx-plugin\n" in trace
    assert "install -y docker.io" not in trace
    assert "systemctl start docker" in trace and "systemctl enable" not in trace


def test_missing_buildx_does_not_authorize_fallback_from_unavailable_endpoint(tmp_path):
    result, trace = installer(
        tmp_path,
        daemon_ready=False,
        compose_ready=True,
        buildx_ready=False,
        candidates="docker-buildx",
        docker_context="unavailable-reviewed-engine",
    )
    assert result.returncode == 1
    assert "configured Docker endpoint" in result.stderr
    assert "apt-" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace


def test_fresh_docker_group_wrapper_verifies_buildx_before_recovery(tmp_path):
    result, trace = installer(
        tmp_path, daemon_ready=False, buildx_ready=False, fresh_group=True, candidates="docker-compose-v2 docker-buildx"
    )
    assert result.returncode == 91, result.stderr
    assert "usermod -aG docker qualifier" in trace
    assert "sg docker -c docker info" in trace
    assert "sg docker -c docker buildx version" in trace
    assert trace.index("sg docker -c docker buildx version") < trace.index("recovery-boundary")
    assert "UNEXPECTED" not in trace


@pytest.mark.parametrize(
    "action,package",
    [("Inst", "docker.io"), ("Conf", "docker.io"), ("Inst", "containerd.io:amd64"), ("Inst", "docker-ce-cli")],
)
def test_remote_engine_cli_repair_refuses_local_engine_or_runtime_apt_closure(tmp_path, action, package):
    plan = f"0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n{action} {package} (1.0 Ubuntu [amd64])\n"
    result, trace = installer(
        tmp_path,
        compose_ready=True,
        buildx_ready=False,
        candidates="docker-buildx",
        docker_host="ssh://reviewed-remote/var/run/docker.sock",
        apt_plan=plan,
    )
    assert result.returncode == 1
    assert "APT plan" in result.stderr
    assert "apt-get --no-remove install" not in trace
    assert "systemctl" not in trace and "recovery-boundary" not in trace


def test_cli_repair_validates_exact_plugin_argv_and_locale_before_install(tmp_path):
    plan = """Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libexample1
Suggested packages:
  example-doc
The following NEW packages will be installed:
  docker-buildx
The following packages will be upgraded:
  libexample1
1 upgraded, 1 newly installed, 0 to remove and 12 not upgraded.
Inst libexample1 [1.0] (1.1 Ubuntu:24.04/noble-updates [amd64])
Inst docker-buildx (0.20 Ubuntu:24.04/noble [amd64])
Conf libexample1 (1.1 Ubuntu:24.04/noble-updates [amd64])
Conf docker-buildx (0.20 Ubuntu:24.04/noble [amd64])
"""
    result, trace = installer(
        tmp_path, compose_ready=True, buildx_ready=False, candidates="docker-buildx", apt_plan=plan
    )
    assert result.returncode == 91, result.stderr
    simulated = "apt-get --simulate --no-remove install -y docker-buildx\n"
    actual = "apt-get --no-remove install -y docker-buildx\n"
    assert trace.index(simulated) < trace.index(actual) < trace.index("recovery-boundary")
    assert "apt-plan-locale C\n" in trace
    assert "systemctl" not in trace


def test_stopped_existing_engine_rejects_apt_engine_upgrade_before_service_start(tmp_path):
    plan = """1 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Inst docker-ce [28.0] (29.0 Docker [amd64])
Inst docker-buildx-plugin (0.20 Docker [amd64])
Conf docker-ce (29.0 Docker [amd64])
Conf docker-buildx-plugin (0.20 Docker [amd64])
"""
    result, trace = installer(
        tmp_path,
        daemon_ready=False,
        compose_ready=True,
        buildx_ready=False,
        installed="docker-ce",
        candidates="docker-buildx-plugin",
        apt_plan=plan,
    )
    assert result.returncode == 1
    assert "APT plan" in result.stderr
    assert "apt-get --no-remove install" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace


def test_unrecognized_simulation_stderr_refuses_even_with_valid_stdout_plan(tmp_path):
    result, trace = installer(
        tmp_path,
        compose_ready=True,
        buildx_ready=False,
        candidates="docker-buildx",
        simulation_stderr="W: unrecognized transaction warning",
    )
    assert result.returncode == 1
    assert "APT plan" in result.stderr
    assert "apt-get --no-remove install" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace


@pytest.mark.parametrize(
    "plan,simulation_exit",
    [
        ("", 0),
        ("unrecognized plan text", 0),
        ("0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nInst docker-buildx\n", 0),
        ("0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv old-package [1.0]\n", 0),
        ("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nPurg old-package\n", 0),
        (
            "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\nInst docker-buildx (1.0 Ubuntu [amd64])\n",
            0,
        ),
        (
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
            0,
        ),
        ("E: unresolved dependencies", 100),
    ],
)
def test_failed_or_unparseable_cli_plan_never_installs_or_starts_services(tmp_path, plan, simulation_exit):
    result, trace = installer(
        tmp_path,
        compose_ready=True,
        buildx_ready=False,
        candidates="docker-buildx",
        apt_plan=plan,
        simulation_exit=simulation_exit,
    )
    assert result.returncode == 1
    assert "APT plan" in result.stderr
    assert "apt-get --no-remove install" not in trace and "systemctl" not in trace
    assert "recovery-boundary" not in trace


@pytest.mark.parametrize(
    "package",
    [
        "docker.io",
        "docker-ce",
        "docker-ce-cli",
        "docker-ce-rootless-extras",
        "containerd",
        "containerd.io",
        "runc",
        "moby-engine",
        "moby-cli",
        "moby-containerd",
        "moby-runc",
        "docker-engine",
        "podman-docker",
        "crun",
    ],
)
@pytest.mark.parametrize("action", ["Inst", "Conf"])
def test_actual_plan_validator_rejects_arch_qualified_engine_and_runtime_actions(package, action):
    # Exercise the real helper parser; bounded is the only command double and
    # supplies a synthetic transaction instead of calling any package manager.
    actions = [action, "Conf" if action == "Inst" else "Inst"]
    for name, accepted in (("libexample1", True), (package, False)):
        environment = {
            **os.environ,
            "APT_PLAN": (
                "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"
                + "".join(f"{item} {name}:amd64 (1.0 Ubuntu [amd64])\n" for item in actions)
            ),
        }
        result = subprocess.run(  # noqa: S603 - fixed helper and stubbed bounded function
            [
                BASH,
                "-c",
                'source "$1"; bounded() { printf "%s\\n" "$APT_PLAN"; }; linux_cli_apt_plan_is_safe "" docker-buildx',
                "validator",
                str(ROOT / "scripts/linux-docker-packages.sh"),
            ],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        assert (result.returncode == 0) is accepted
        assert not result.stdout


def test_cold_local_engine_install_remains_explicitly_authorized_without_cli_only_plan(tmp_path):
    result, trace = installer(
        tmp_path,
        daemon_ready=False,
        buildx_ready=False,
        candidates="docker-compose-v2 docker-buildx",
        apt_plan="malformed unused plan",
    )
    assert result.returncode == 91, result.stderr
    assert "apt-get --simulate" not in trace
    assert "apt-get --no-remove install -y docker.io docker-compose-v2 docker-buildx\n" in trace
    assert "systemctl enable --now docker" in trace
