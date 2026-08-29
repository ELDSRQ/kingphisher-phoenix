import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESTORE = (ROOT / "scripts/operator/remote-docker-worker/restore-state.sh").read_text()
EXTERNAL_ENGINE = (ROOT / "scripts/operator/remote-docker-worker/external-engine.sh").read_text()
REMOTE_PREFLIGHT = (ROOT / "scripts/operator/remote-docker-worker/preflight.sh").read_text()
REMOTE_BOOTSTRAP = (ROOT / "scripts/operator/remote-docker-worker/bootstrap-macos.command").read_text()
POSTGRES_INIT = (ROOT / "infrastructure/containers/postgres-init/001-roles.sh").read_text()


def _write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def test_restore_defaults_to_the_unambiguous_current_checkpoint() -> None:
    assert "$KP_ROOT/migration-checkpoint/postgres.dump" in RESTORE
    assert "$KP_ROOT/migration-checkpoint/redis.rdb" in RESTORE
    assert "KP_POSTGRES_DUMP:-" not in RESTORE
    assert "KP_REDIS_RDB:-" not in RESTORE
    assert "$KP_ROOT/artifacts/postgres.dump" not in RESTORE
    assert "$KP_ROOT/artifacts/redis.rdb" not in RESTORE


def test_restore_refuses_existing_project_state_before_apply() -> None:
    container_guard = "target container already exists: $KP_NAME"
    volume_guard = "target volume already exists: $KP_NAME"
    apply_gate = 'if [ "$KP_APPLY" -ne 1 ]'

    assert container_guard in RESTORE
    assert volume_guard in RESTORE
    assert RESTORE.index(container_guard) < RESTORE.index(apply_gate)
    assert RESTORE.index(volume_guard) < RESTORE.index(apply_gate)


def test_restore_requires_the_exact_external_engine_environment() -> None:
    apply_gate = 'if [ "$KP_APPLY" -ne 1 ]'
    guards = (
        "KP_EXPECTED_DOCKER_HOST='unix:///Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock'",
        "KP_EXPECTED_DOCKER_CONFIG='/Volumes/DockerExternal/KingPhisher-Phoenix/docker-client'",
        "restore must be launched through external-engine.sh run; ambient Docker is prohibited",
        "DOCKER_CONTEXT must be unset so legacy contexts cannot override the external socket",
        '"$KP_EXTERNAL_ENGINE" preflight',
        "colima-kingphisher|aarch64|/var/lib/docker",
    )

    assert all(guard in RESTORE for guard in guards)
    assert RESTORE.index("require_external_engine_invocation") < RESTORE.index(apply_gate)


def test_restore_rejects_ambient_docker_before_invoking_the_cli(tmp_path: Path) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker_log = tmp_path / "docker.log"
    _write_executable(
        binaries / "docker",
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$KP_DOCKER_LOG"\nexit 99\n',
    )
    environment = os.environ.copy()
    environment.update(
        {
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "KP_DOCKER_LOG": str(docker_log),
            "PATH": f"{binaries}:{environment['PATH']}",
        }
    )
    environment.pop("DOCKER_CONTEXT", None)

    result = subprocess.run(  # noqa: S603
        ["/bin/bash", str(ROOT / "scripts/operator/remote-docker-worker/restore-state.sh")],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "ambient Docker is prohibited" in result.stderr
    assert not docker_log.exists()


def test_restore_clean_target_guard_covers_all_compose_project_resources() -> None:
    apply_gate = 'if [ "$KP_APPLY" -ne 1 ]'
    container_guard = "label=com.docker.compose.project=$KP_PROJECT_NAME"
    volume_guard = "docker volume ls -q"
    network_guard = "docker network ls -q"

    assert "target engine already contains Compose project containers" in RESTORE
    assert "target engine already contains Compose project volumes" in RESTORE
    assert "target engine already contains Compose project networks" in RESTORE
    assert RESTORE.index(container_guard) < RESTORE.index(apply_gate)
    assert RESTORE.index(volume_guard) < RESTORE.index(apply_gate)
    assert RESTORE.index(network_guard) < RESTORE.index(apply_gate)


def test_postgres_restore_is_proven_in_disposable_database_first() -> None:
    create_verify = 'createdb -U kingphisher "$KP_VERIFY_DB"'
    restore_verify = '-U kingphisher -d "$KP_VERIFY_DB" --exit-on-error --single-transaction'
    drop_verify = 'dropdb -U kingphisher --force "$KP_VERIFY_DB"'
    assert_target_empty = '[ "$KP_TARGET_TABLES" -eq 0 ]'
    restore_target = "-U kingphisher -d kingphisher --exit-on-error --single-transaction"

    assert RESTORE.index(create_verify) < RESTORE.index(restore_verify)
    assert RESTORE.index(restore_verify) < RESTORE.index(drop_verify)
    assert RESTORE.index(drop_verify) < RESTORE.index(assert_target_empty)
    assert RESTORE.index(assert_target_empty) < RESTORE.index(restore_target)


def test_redis_rdb_is_materialized_before_normal_service_starts() -> None:
    create_stopped = "docker compose create redis"
    copy_rdb = 'docker cp "$KP_REDIS_RDB" "$KP_REDIS_CONTAINER:/data/dump.rdb"'
    materializer = '"$KP_REDIS_IMAGE" redis-server'
    disable_aof = "--requirepass \"$KP_REDIS_PASSWORD\" --appendonly no --save ''"
    enable_aof = "redis-cli --no-auth-warning CONFIG SET appendonly yes"
    start_normal = 'docker start "$KP_REDIS_CONTAINER"'

    assert RESTORE.index(create_stopped) < RESTORE.index(copy_rdb)
    assert RESTORE.index(copy_rdb) < RESTORE.index(materializer)
    assert disable_aof in RESTORE
    assert RESTORE.index(materializer) < RESTORE.index(enable_aof)
    assert RESTORE.index(enable_aof) < RESTORE.index(start_normal)
    assert '[ "$KP_REDIS_KEYS_AFTER" = "$KP_REDIS_KEYS_BEFORE" ]' in RESTORE
    assert '[ "$KP_REDIS_KEYS_15_AFTER" = "$KP_REDIS_KEYS_15_BEFORE" ]' in RESTORE


def test_restore_has_no_project_state_cleanup_lane() -> None:
    forbidden = (
        "docker compose down",
        "docker volume rm",
        "docker system prune",
        "docker builder prune",
        "docker buildx prune",
        "rm -rf",
    )
    assert not any(command in RESTORE for command in forbidden)


def test_postgres_initializer_uses_fixed_image_shell() -> None:
    assert POSTGRES_INIT.startswith("#!/bin/sh\n")
    assert "set -eu\n" in POSTGRES_INIT
    assert "/usr/bin/env" not in POSTGRES_INIT.splitlines()[0]


def test_external_engine_is_bound_to_the_reviewed_volume_and_profile() -> None:
    assert "KP_EXTERNAL_VOLUME=/Volumes/DockerExternal" in EXTERNAL_ENGINE
    assert "FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4" in EXTERNAL_ENGINE
    assert "KP_COLIMA_PROFILE=kingphisher" in EXTERNAL_ENGINE
    assert 'KP_DOCKER_SOCKET="$KP_COLIMA_HOME/$KP_COLIMA_PROFILE/docker.sock"' in EXTERNAL_ENGINE
    assert "KP_PROJECT_SOURCE=/Users/edierks/Projects/kingphisher-phoenix" in EXTERNAL_ENGINE
    assert "KP_EXPECTED_AMBIENT_CONTEXT=desktop-linux" in EXTERNAL_ENGINE
    for forbidden_override in (
        "KP_EXTERNAL_VOLUME:-",
        "KP_EXTERNAL_VOLUME_UUID:-",
        "KP_COLIMA_PROFILE:-",
        "KP_COLIMA_HOME:-",
        "KP_PROJECT_DOCKER_CONFIG:-",
        "KP_PROJECT_SOURCE:-",
        "KP_EXPECTED_AMBIENT_CONTEXT:-",
    ):
        assert forbidden_override not in EXTERNAL_ENGINE
    assert '"credsStore":"osxkeychain"' in EXTERNAL_ENGINE
    assert '"cliPluginsExtraDirs"' in EXTERNAL_ENGINE
    assert "/Applications/Docker.app/Contents/Resources/cli-plugins" in EXTERNAL_ENGINE
    assert "/opt/homebrew/lib/docker/cli-plugins" in EXTERNAL_ENGINE
    assert '"$KP_DOCKER_CLI_PLUGIN_DIR/docker-compose"' in EXTERNAL_ENGINE
    assert '"$KP_DOCKER_CLI_PLUGIN_DIR/docker-buildx"' in EXTERNAL_ENGINE
    assert 'data.get("cliPluginsExtraDirs") != [sys.argv[2]]' in EXTERNAL_ENGINE
    assert "inline registry tokens are prohibited" in EXTERNAL_ENGINE


def test_external_engine_fails_closed_without_docker_desktop_fallback() -> None:
    assert "Docker Desktop is not a fallback" in EXTERNAL_ENGINE
    assert "docker_desktop_fallback=prohibited" in EXTERNAL_ENGINE
    assert 'DOCKER_HOST="unix://$KP_DOCKER_SOCKET"' in EXTERNAL_ENGINE
    assert "docker context use" not in EXTERNAL_ENGINE
    assert "docker --context desktop-linux" not in EXTERNAL_ENGINE
    assert "colima-$KP_COLIMA_PROFILE|aarch64|/var/lib/docker" in EXTERNAL_ENGINE
    assert "native Apple Silicon" in EXTERNAL_ENGINE
    assert "project Docker socket is absent or symbolic" in EXTERNAL_ENGINE
    assert "canonical project source is missing or symbolic" in EXTERNAL_ENGINE


def test_external_engine_scopes_full_project_commands_to_the_canonical_source() -> None:
    assert "project_environment()" in EXTERNAL_ENGINE
    assert "COMPOSE_PROJECT_NAME=phishing-awareness-platform" in EXTERNAL_ENGINE
    assert 'printf "export DOCKER_CONFIG=' in EXTERNAL_ENGINE
    assert 'cd "$KP_PROJECT_SOURCE"' in EXTERNAL_ENGINE
    run_case = EXTERNAL_ENGINE.split("  run)", maxsplit=1)[1].split("  *) usage", maxsplit=1)[0]
    assert "require_project_engine" in run_case
    assert 'project_environment "$@"' in run_case
    assert "eval " not in run_case
    env_case = EXTERNAL_ENGINE.split("  env)", maxsplit=1)[1].split("  docker)", maxsplit=1)[0]
    assert "unset DOCKER_CONTEXT" in env_case


def test_external_engine_start_preserves_ambient_context_and_disables_rosetta() -> None:
    assert "--activate=false" in EXTERNAL_ENGINE
    assert "--vz-rosetta=false" in EXTERNAL_ENGINE
    assert "--binfmt=false" in EXTERNAL_ENGINE
    assert EXTERNAL_ENGINE.index('KP_CONTEXT_BEFORE="$(ambient_context)"') < EXTERNAL_ENGINE.index(
        'KP_CONTEXT_AFTER="$(ambient_context)"'
    )
    assert "ambient Docker context changed" in EXTERNAL_ENGINE
    assert '--mount "$KP_PROJECT_SOURCE"' in EXTERNAL_ENGINE
    assert '--mount "$KP_PROJECT_SOURCE:w"' not in EXTERNAL_ENGINE
    assert "canonical source must be mounted into Colima read-only" in EXTERNAL_ENGINE
    assert "Colima profile unexpectedly enables Kubernetes" in EXTERNAL_ENGINE
    assert "Colima profile must not expose a writable host mount" in EXTERNAL_ENGINE


def test_remote_preflight_targets_external_helper_not_shared_remote_context() -> None:
    assert '"$KP_REMOTE_PROJECT_DIR/scripts/operator/remote-docker-worker/external-engine.sh"' in REMOTE_PREFLIGHT
    assert "  preflight)" in REMOTE_PREFLIGHT
    assert "external_free_kib" in REMOTE_PREFLIGHT
    assert "docker --context" not in REMOTE_PREFLIGHT
    assert "kp-remote-mac" not in REMOTE_PREFLIGHT
    assert "KP_EXPECTED_CONTROLLER_CONTEXT=desktop-linux" in REMOTE_PREFLIGHT
    assert "DOCKER_HOST must be unset for controller preflight" in REMOTE_PREFLIGHT
    assert "DOCKER_CONTEXT must be unset for controller preflight" in REMOTE_PREFLIGHT
    assert "DOCKER_CONFIG must be unset for controller preflight" in REMOTE_PREFLIGHT
    assert "StrictHostKeyChecking=yes" in REMOTE_PREFLIGHT


def test_external_worker_tools_have_no_cleanup_lane() -> None:
    combined = EXTERNAL_ENGINE + REMOTE_PREFLIGHT + REMOTE_BOOTSTRAP
    forbidden = (
        "docker compose down",
        "docker volume rm",
        "docker system prune",
        "docker builder prune",
        "docker buildx prune",
        "colima delete",
        "rm -rf",
    )
    assert not any(command in combined for command in forbidden)


def test_remote_bootstrap_uses_external_engine_without_starting_docker_desktop() -> None:
    assert 'KP_EXTERNAL_ENGINE="$KP_SCRIPT_DIR/external-engine.sh"' in REMOTE_BOOTSTRAP
    assert '"$KP_EXTERNAL_ENGINE" start' in REMOTE_BOOTSTRAP
    assert "docker_desktop_modified=false" in REMOTE_BOOTSTRAP
    assert "docker desktop start" not in REMOTE_BOOTSTRAP
    assert "open -gja Docker" not in REMOTE_BOOTSTRAP
    assert "--cask docker" not in REMOTE_BOOTSTRAP
    assert "native Apple Silicon" in REMOTE_BOOTSTRAP
    assert "FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4" in REMOTE_BOOTSTRAP
    assert 'mktemp "$KP_RESULT_DIRECTORY/remote-worker-result.XXXXXX"' in REMOTE_BOOTSTRAP
    assert 'KP_RESULT_FILE="$KP_SCRIPT_DIR/remote-worker-result.txt"' not in REMOTE_BOOTSTRAP
    assert "brew install docker-credential-helper" in REMOTE_BOOTSTRAP
    assert "brew install docker-compose docker-buildx" in REMOTE_BOOTSTRAP
