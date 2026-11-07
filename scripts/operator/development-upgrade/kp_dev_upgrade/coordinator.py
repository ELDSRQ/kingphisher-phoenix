"""Explicit phases; no reset, cleanup, credential rotation, or automatic rollback."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import tarfile
import time
from pathlib import Path
from typing import Any

import httpx
import redis
from sqlalchemy import MetaData, Table, create_engine, func, inspect, select, text
from sqlalchemy.engine import make_url

from kp_dev_upgrade.core import (
    CONTAINERS,
    LABEL,
    NORMAL,
    OLD_SCHEMA,
    RELEASES,
    RUNS,
    SERVICE,
    UNIT,
    Blocked,
    Commands,
    canonical,
    configuration,
    digest,
    environment,
    phase_receipt,
    private_bytes,
    private_json,
    read_json,
    release_manifest,
    require_clean_connection_environment,
)
from kp_dev_upgrade.preflight import MAX_REDIS_KEYS, bounds_preflight, queue_snapshot, require_send_queues_drained

CGROUP_ROOT = Path("/sys/fs/cgroup")


def owned_port(record: dict[str, Any], identifier: str, run_id: str, port: str) -> int:
    """Reject missing, wildcard, extra or stale container publications."""
    if (
        record.get("Id") != identifier
        or record.get("Config", {}).get("Labels", {}).get(LABEL) != run_id
        or record.get("State", {}).get("Running") is not True
    ):
        raise Blocked("rehearsal_container_identity_mismatch")
    ports = record.get("NetworkSettings", {}).get("Ports")
    if not isinstance(ports, dict) or set(ports) != {port}:
        raise Blocked("rehearsal_requires_exact_loopback_mapping")
    bindings = ports[port]
    if (
        not isinstance(bindings, list)
        or len(bindings) != 1
        or bindings[0].get("HostIp") != "127.0.0.1"
        or not re.fullmatch("[0-9]{1,5}", str(bindings[0].get("HostPort", "")))
    ):
        raise Blocked("rehearsal_requires_exact_loopback_mapping")
    result = int(bindings[0]["HostPort"])
    if not 32768 <= result <= 65535 or result in {51457, 51458, 51459}:
        raise Blocked("rehearsal_port_conflicts_with_preserved_runtime")
    return result


def redis_inventory(client: Any) -> dict[str, Any]:
    """Hash contents, retain expiry times, and bound private snapshot diagnostics."""
    result: dict[str, Any] = {}
    deadline = time.monotonic() + 120
    cursor = 0
    processed = total_bytes = 0
    while True:
        cursor, keys = client.scan(cursor=cursor, count=500)
        for offset in range(0, len(keys), 500):
            chunk = keys[offset : offset + 500]
            processed += len(chunk)
            if processed > MAX_REDIS_KEYS * 2 or time.monotonic() >= deadline:
                raise Blocked("redis_inventory_bound_exceeded")
            pipeline = client.pipeline(transaction=False)
            for key in chunk:
                pipeline.type(key)
                pipeline.pttl(key)
            values = pipeline.execute()
            observed_ms = int(time.time() * 1000)
            content = client.pipeline(transaction=False)
            selected = []
            for index, key in enumerate(chunk):
                raw_kind, ttl = values[index * 2 : index * 2 + 2]
                kind = raw_kind.decode() if isinstance(raw_kind, bytes) else raw_kind
                if kind == "none" or ttl == -2:
                    continue
                if kind == "string":
                    content.get(key)
                elif kind == "list":
                    content.lrange(key, 0, -1)
                elif kind == "hash":
                    content.hgetall(key)
                elif kind == "set":
                    content.smembers(key)
                elif kind == "zset":
                    content.zrange(key, 0, -1, withscores=True)
                elif kind == "stream":
                    # Raw nested arrays retain duplicate stream field names.
                    content.execute_command("EVAL_RO", "return redis.call('XRANGE', KEYS[1], '-', '+')", 1, key)
                else:
                    raise Blocked("redis_inventory_unsupported_module_type")
                selected.append((key, kind, ttl))
            for (key, kind, ttl), payload in zip(selected, content.execute(), strict=True):
                if payload is None:
                    continue
                checksum, payload_bytes = logical_redis_digest(kind, payload)
                total_bytes += payload_bytes
                if total_bytes > 512 * 1024 * 1024:
                    raise Blocked("redis_serialized_inventory_byte_bound_exceeded")
                name = hashlib.sha256(key if isinstance(key, bytes) else key.encode()).hexdigest()
                result[name] = {
                    "sha256": checksum,
                    "expires_ms": None if ttl == -1 else observed_ms + ttl,
                }
                if len(result) > MAX_REDIS_KEYS:
                    raise Blocked("redis_inventory_bound_exceeded")
            if time.monotonic() >= deadline:
                raise Blocked("redis_inventory_deadline")
        if cursor == 0:
            break
    return result


def logical_redis_digest(kind: str, payload: Any) -> tuple[str, int]:
    """Hash logical values independently of Redis hash/set physical encoding."""
    checksum = hashlib.sha256(kind.encode())
    total = 0

    def add(value: Any) -> None:
        nonlocal total
        if isinstance(value, bytes):
            checksum.update(b"b" + len(value).to_bytes(8, "big") + value)
            total += len(value)
        elif isinstance(value, float):
            add(value.hex().encode())
        elif isinstance(value, dict):
            checksum.update(b"d" + len(value).to_bytes(8, "big"))
            for key in sorted(value):
                add(key)
                add(value[key])
        elif isinstance(value, set):
            checksum.update(b"s" + len(value).to_bytes(8, "big"))
            for element in sorted(value):
                add(element)
        elif isinstance(value, (list, tuple)):
            checksum.update(b"l" + len(value).to_bytes(8, "big"))
            for element in value:
                add(element)
        else:
            raise Blocked("redis_inventory_unsupported_logical_value")

    add(payload)
    return checksum.hexdigest(), total


def compare_redis_inventory(before: dict[str, Any], after: dict[str, Any]) -> None:
    now = int(time.time() * 1000)
    if set(after) - set(before):
        raise Blocked("redis_restore_has_unexpected_keys")
    for key, value in before.items():
        actual = after.get(key)
        if actual is None:
            if value["expires_ms"] is None or value["expires_ms"] > now:
                raise Blocked("redis_restore_missing_unexpired_key")
            continue
        if value["sha256"] != actual["sha256"]:
            raise Blocked("redis_restore_value_differs")
        if (value["expires_ms"] is None) != (actual["expires_ms"] is None):
            raise Blocked("redis_restore_expiry_kind_differs")
        if value["expires_ms"] is not None and abs(value["expires_ms"] - actual["expires_ms"]) > 1000:
            raise Blocked("redis_restore_expiry_differs")


def archive_index(archive_path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    with tarfile.open(archive_path, "r") as archive:
        for member in archive:
            path = Path(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or member.name in result
                or not (member.isfile() or member.isdir())
            ):
                raise Blocked("project_archive_unsafe_or_incomplete_member")
            if member.isfile():
                if len(result) >= 20000:
                    raise Blocked("project_archive_inventory_bound")
                stream = archive.extractfile(member)
                if stream is None:
                    raise Blocked("project_archive_member_unreadable")
                checksum = hashlib.sha256()
                while block := stream.read(1024 * 1024):
                    checksum.update(block)
                result[member.name] = checksum.hexdigest()
    if not {".env", "unit/kp-supervisor.service"} <= result.keys() or not any(
        name.startswith("data/") for name in result
    ):
        raise Blocked("project_archive_required_state_missing")
    return result


def summary(url: str) -> dict[str, Any]:
    require_clean_connection_environment()
    engine = create_engine(
        url,
        connect_args={
            "connect_timeout": 3,
            "options": "-c default_transaction_read_only=on -c statement_timeout=15000",
        },
    )
    try:
        with engine.connect() as connection:
            counts = {
                name: int(
                    connection.scalar(select(func.count()).select_from(Table(name, MetaData(), schema="public"))) or 0
                )
                for name in inspect(connection).get_table_names(schema="public")
            }
            return {
                "schema": connection.scalar(text("SELECT version_num FROM alembic_version")),
                "table_counts": counts,
                "audit_head": dict(
                    connection.execute(text("SELECT event_hash,signature FROM audit_chain_head WHERE id=1"))
                    .mappings()
                    .one()
                ),
                "queued_assignments": int(
                    connection.scalar(
                        text(
                            "SELECT count(*) FROM recipient_assignments "
                            "WHERE lower(send_state::text) NOT IN ('accepted','failed','delivered','expired')"
                        )
                    )
                    or 0
                ),
                "pending_outbox": int(
                    connection.scalar(text("SELECT count(*) FROM transactional_outbox WHERE status <> 'dispatched'"))
                    or 0
                ),
            }
    finally:
        engine.dispose()


class Upgrade:
    def __init__(self, run: Path, commands: Commands | None = None):
        self.run = canonical(run)
        if self.run.parent != RUNS or not re.fullmatch(
            r"development-upgrade-[0-9]{8}T[0-9]{6}Z-[a-z0-9]{8,16}", self.run.name
        ):
            raise Blocked("run_path_is_outside_reviewed_namespace")
        self.commands = commands or Commands(self.run / "private-commands.log")

    @property
    def plan(self) -> dict[str, Any]:
        value = read_json(self.run / "plan.json")
        commit = value.get("commit", "")
        suffix = self.run.name.removeprefix("development-upgrade-")
        expected_source = RELEASES / f"{commit}-{suffix}" / "source"
        expected_dropin = UNIT.parent / f"{SERVICE}.d" / f"80-development-upgrade-{suffix}.conf"
        if (
            not re.fullmatch("[0-9a-f]{40}", commit)
            or value.get("source") != str(expected_source)
            or value.get("dropin") != str(expected_dropin)
        ):
            raise Blocked("stored_plan_target_mismatch")
        canonical(expected_source)
        canonical(expected_dropin)
        return value

    def gate(self, *, stopped: bool, switched: bool = False) -> tuple[dict[str, Any], dict[str, str]]:
        plan = self.plan
        actual = self.commands.normal_identity()
        if actual != plan["normal_identity"]:
            raise Blocked("normal_identity_changed_since_prepare")
        cfg = configuration(NORMAL / ".env")
        unit = self.commands.unit()
        expected_root = plan["source"] if switched else str(NORMAL)
        if unit.get("WorkingDirectory") != expected_root or unit.get("FragmentPath") != str(UNIT):
            raise Blocked("normal_service_target_changed")
        expected_dropin = plan["dropin"] if switched else ""
        if unit.get("DropInPaths", "") != expected_dropin:
            raise Blocked("normal_service_dropins_changed")
        if stopped and (unit.get("ActiveState") != "inactive" or unit.get("MainPID") != "0"):
            raise Blocked("normal_application_is_not_quiesced")
        if not stopped and unit.get("ActiveState") != "active":
            raise Blocked("normal_application_is_not_active")
        if stopped:
            groups = {unit.get("ControlGroup", "")}
            before_stop = self.run / "private-before-stop.json"
            if before_stop.exists():
                groups.add(read_json(before_stop)["service"].get("ControlGroup", ""))
            groups.add(read_json(self.run / "private-before-service.json").get("ControlGroup", ""))
            groups.discard("")
            if not groups:
                raise Blocked("normal_service_cgroup_identity_missing")
            deadline = time.monotonic() + 5
            for group in groups:
                path = Path(group)
                if not path.is_absolute() or ".." in path.parts or path.name != SERVICE:
                    raise Blocked("invalid_service_cgroup")
                root = CGROUP_ROOT / group.lstrip("/")
                # Removed cgroups cannot retain processes. Inspect surviving
                # captures even when systemd clears its current ControlGroup.
                if root.exists():
                    for index, member in enumerate(root.rglob("cgroup.procs")):
                        if index >= 256 or time.monotonic() >= deadline:
                            raise Blocked("service_cgroup_inspection_bound")
                        if member.read_text().strip():
                            raise Blocked("normal_application_children_still_running")
        return plan, cfg

    def prepare(self, source: Path, manifest: Path, manifest_hash: str, commit: str) -> None:
        # All identity/source/config checks precede the first new file or directory.
        identity = self.commands.normal_identity()
        configuration(NORMAL / ".env")
        unit = self.commands.unit()
        if (
            unit.get("ActiveState") != "active"
            or unit.get("WorkingDirectory") != str(NORMAL)
            or unit.get("FragmentPath") != str(UNIT)
            or unit.get("DropInPaths")
        ):
            raise Blocked("unexpected_current_service_configuration")
        group = Path(unit.get("ControlGroup", ""))
        if not group.is_absolute() or ".." in group.parts or group.name != SERVICE:
            raise Blocked("active_service_cgroup_identity_missing_or_unsupported")
        files = release_manifest(source, manifest, manifest_hash, commit)
        preflight = bounds_preflight(configuration(NORMAL / ".env"))
        qualified = read_json(manifest)
        if self.run.exists():
            raise Blocked("run_already_exists")
        if shutil.disk_usage(RUNS).free < 8 * 1024**3:
            raise Blocked("insufficient_disk_preserve_assets_and_stop")
        release = RELEASES / f"{commit}-{self.run.name.removeprefix('development-upgrade-')}"
        canonical(release)
        if release.exists():
            raise Blocked("release_already_exists")
        self.run.mkdir(mode=0o700)
        RELEASES.mkdir(mode=0o700, exist_ok=True)
        release.mkdir(mode=0o700)
        target = release / "source"
        target.mkdir(mode=0o700)
        private_json(self.run / "private-before-service.json", unit)
        private_json(self.run / "private-prepare-preflight.json", preflight)
        executables = sorted(name for name in files if (source / name).stat().st_mode & 0o111)
        for name in files:
            output = target / name
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            private_bytes(output, (source / name).read_bytes())
            if name in executables:
                output.chmod(0o700)
        private_bytes(self.run / "qualified-source.json", manifest.read_bytes())
        original_config = (NORMAL / ".env").read_bytes()
        binding = (
            f"\nOPERATOR_API_ENV_FILE={target / '.env'}\n"
            f"OPERATOR_API_CONSOLE_STATIC_DIR={target / 'apps/operator-ui/src/console'}\n"
        )
        private_bytes(target / ".env", original_config + binding.encode())
        (target / "data").symlink_to(NORMAL / "data", target_is_directory=True)
        dropin = (
            UNIT.parent
            / f"{SERVICE}.d"
            / f"80-development-upgrade-{self.run.name.removeprefix('development-upgrade-')}.conf"
        )
        plan = {
            "commit": commit,
            "source": str(target),
            "release": str(release),
            "schema_head": qualified["schema_head"],
            "normal_identity": identity,
            "dropin": str(dropin),
            "qualified_manifest_sha256": manifest_hash,
            "private_config_sha256": digest(target / ".env"),
            "files": files,
            "executables": executables,
            "old_source": str(NORMAL),
            "old_venv": str(NORMAL / ".venv"),
            "normal_state_changes_authorized_only_in_explicit_phases": True,
        }
        private_json(self.run / "plan.json", plan)
        self.commands.run(
            ["/home/builder/.local/bin/uv", "sync", "--frozen", "--all-packages", "--project", str(target)], timeout=900
        )
        if not (target / ".venv/bin/python").is_file():
            raise Blocked("new_frozen_environment_missing")
        private_json(self.run / "prepared.json", {"passed": True, "commit": commit})

    def checkpoint(self) -> None:
        plan, cfg = self.gate(stopped=False)
        phase_receipt(self.run / "prepared.json")
        self._source(plan)
        if (self.run / "checkpoint.json").exists() or (self.run / "checkpoint").exists():
            raise Blocked("checkpoint_collision")
        before = summary(cfg["DATABASE_URL"])
        if before["schema"] != OLD_SCHEMA or before["queued_assignments"] or before["pending_outbox"]:
            raise Blocked("normal_workload_not_at_reviewed_checkpoint_boundary")
        preflight = bounds_preflight(cfg)
        before_queues = queue_snapshot(cfg["REDIS_URL"])
        require_send_queues_drained(before_queues)
        private_json(
            self.run / "private-before-stop.json",
            {
                "service": self.commands.unit(),
                "database": before,
                "bounds_preflight": preflight,
                "queue_stats": before_queues,
            },
        )
        self.commands.run(["systemctl", "--user", "stop", SERVICE], timeout=180)
        self.gate(stopped=True)
        quiesced = summary(cfg["DATABASE_URL"])
        if quiesced["schema"] != OLD_SCHEMA or quiesced["queued_assignments"] or quiesced["pending_outbox"]:
            raise Blocked("quiesced_workload_not_at_checkpoint_boundary_leave_stopped")
        quiesced_queues = queue_snapshot(cfg["REDIS_URL"])
        require_send_queues_drained(quiesced_queues)
        checkpoint = self.run / "checkpoint"
        checkpoint.mkdir(mode=0o700)
        pg = CONTAINERS["postgres"]
        self.commands.docker(
            "exec",
            pg,
            "pg_dumpall",
            "-U",
            "kingphisher",
            "--globals-only",
            output=checkpoint / "globals.sql",
            timeout=180,
        )
        self.commands.docker(
            "exec",
            pg,
            "pg_dump",
            "-U",
            "kingphisher",
            "-d",
            "kingphisher",
            "-Fc",
            output=checkpoint / "postgres.dump",
            timeout=180,
        )
        self.commands.docker(
            "exec", "-i", pg, "pg_restore", "--list", input=(checkpoint / "postgres.dump").read_bytes(), timeout=60
        )
        cache = redis.Redis.from_url(cfg["REDIS_URL"], socket_timeout=5, socket_connect_timeout=3)
        try:
            if cache.info("persistence")["rdb_bgsave_in_progress"]:
                raise Blocked("redis_existing_save_in_progress")
            saved_after = int(time.time())
            cache.bgsave()
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                state = cache.info("persistence")
                if (
                    not state["rdb_bgsave_in_progress"]
                    and state["rdb_last_bgsave_status"] == "ok"
                    and state["rdb_last_save_time"] >= saved_after
                ):
                    break
                time.sleep(0.25)
            else:
                raise Blocked("redis_checkpoint_deadline")
            config = cache.config_get("dir") | cache.config_get("dbfilename")
            directory = config.get("dir", b"")
            filename = config.get("dbfilename", b"")
            directory = directory.decode() if isinstance(directory, bytes) else directory
            filename = filename.decode() if isinstance(filename, bytes) else filename
            if directory != "/data" or filename != "dump.rdb":
                raise Blocked("redis_persistence_layout_changed")
            redis_state = redis_inventory(cache)
        finally:
            cache.close()
        private_json(checkpoint / "redis-inventory.json", redis_state)
        content = self.commands.docker("cp", f"{CONTAINERS['redis']}:/data/dump.rdb", "-", timeout=90)
        with tarfile.open(fileobj=io.BytesIO(content)) as archive:
            members = archive.getmembers()
            if len(members) != 1 or not members[0].isfile() or members[0].name != "dump.rdb":
                raise Blocked("unexpected_redis_archive")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise Blocked("redis_checkpoint_missing")
            private_bytes(checkpoint / "redis.rdb", stream.read())
        archive_path = checkpoint / "project-state.tar"
        with (
            os.fdopen(os.open(archive_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as output,
            tarfile.open(fileobj=output, mode="w") as archive,
        ):
            for name in (".env", "docker-compose.override.yml", "data"):
                path = NORMAL / name
                if path.exists():
                    archive.add(path, arcname=name, recursive=True)
            archive.add(UNIT, arcname="unit/kp-supervisor.service")
        project_files = archive_index(archive_path)
        after = summary(cfg["DATABASE_URL"])
        if after != quiesced:
            raise Blocked("normal_database_changed_during_quiesced_capture")
        private_json(
            self.run / "checkpoint.json",
            {
                "passed": True,
                "database": after,
                "queue_stats": quiesced_queues,
                "project_files": project_files,
                "files": {path.name: digest(path) for path in checkpoint.iterdir() if path.is_file()},
                "project_state_scope": "configuration_data_logs_witness_and_unit; Mailpit container remains preserved",
                "normal_containers_preserved": plan["normal_identity"]["containers"],
            },
        )

    def _checkpoint(self) -> dict[str, Any]:
        value = read_json(self.run / "checkpoint.json")
        if value.get("passed") is not True:
            raise Blocked("checkpoint_not_verified")
        for name, expected in value["files"].items():
            path = self.run / "checkpoint" / name
            if Path(name).name != name or digest(path) != expected:
                raise Blocked("checkpoint_integrity_mismatch")
        if archive_index(self.run / "checkpoint/project-state.tar") != value["project_files"]:
            raise Blocked("project_archive_member_integrity_mismatch")
        return value

    def _probe(self, interpreter: Path, source: Path, cfg: dict[str, str], output: str) -> dict[str, Any]:
        script = Path(self.plan["source"]) / "scripts/operator/development-upgrade/kp_dev_upgrade/probe.py"
        self.commands.run(
            [str(interpreter), str(script), "--output", str(self.run / output)],
            env=environment(dict(cfg, PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=30000")),
            cwd=source,
            timeout=180,
        )
        result = read_json(self.run / output)
        if result.get("passed") is not True or not Path(result["module_path"]).is_relative_to(source):
            raise Blocked("code_or_key_compatibility_proof_failed")
        return result

    def _source(self, plan: dict[str, Any]) -> Path:
        source = canonical(Path(plan["source"]))
        if digest(source / ".env") != plan["private_config_sha256"]:
            raise Blocked("private_configuration_drift")
        executable_names = plan.get("executables")
        if (
            not isinstance(executable_names, list)
            or any(not isinstance(name, str) for name in executable_names)
            or len(set(executable_names)) != len(executable_names)
            or not set(executable_names) <= plan["files"].keys()
        ):
            raise Blocked("prepared_source_executable_manifest_changed")
        for name, expected in plan["files"].items():
            member = canonical(source / name)
            if digest(member) != expected:
                raise Blocked("prepared_source_changed")
            expected_mode = 0o700 if name in executable_names else 0o600
            if member.stat().st_mode & 0o7777 != expected_mode:
                raise Blocked("prepared_source_mode_changed")
        if not (source / "data").is_symlink() or (source / "data").readlink() != NORMAL / "data":
            raise Blocked("shared_data_binding_changed")
        return source

    def rehearse(self) -> None:
        plan, cfg = self.gate(stopped=True)
        source = self._source(plan)
        checkpoint = self._checkpoint()
        if (self.run / "rehearsal.json").exists() or (self.run / "private-rehearsal-resources.json").exists():
            raise Blocked("rehearsal_collision")
        run_id = self.run.name.removeprefix("development-upgrade-")
        name = f"kp-development-upgrade-{run_id}-postgres"
        image = plan["normal_identity"]["containers"]["postgres"]["image"]
        for kind in ("postgres", "redis"):
            image_metadata = json.loads(
                self.commands.docker(
                    "image",
                    "inspect",
                    plan["normal_identity"]["containers"][kind]["image"],
                    "--format",
                    '{"os":{{json .Os}},"arch":{{json .Architecture}}}',
                )
            )
            if image_metadata != {"os": "linux", "arch": "amd64"}:
                raise Blocked("rehearsal_requires_existing_native_amd64_image")
        envfile = self.run / "private-rehearsal-postgres.env"
        owner = make_url(cfg["DATABASE_URL"])
        private_bytes(
            envfile,
            f"POSTGRES_USER=kingphisher\nPOSTGRES_DB=kingphisher\nPOSTGRES_PASSWORD={owner.password}\n".encode(),
        )
        volume = name + "-data"
        self._resource_available(name, volume)
        private_json(
            self.run / "private-rehearsal-intent.json",
            {"postgres_name": name, "postgres_volume": volume, "label": run_id},
        )
        self.commands.docker("volume", "create", "--label", f"{LABEL}={run_id}", volume)
        identifier = (
            self.commands.docker(
                "run",
                "-d",
                "--pull",
                "never",
                "--name",
                name,
                "--label",
                f"{LABEL}={run_id}",
                "--memory",
                "1g",
                "--cpus",
                "2",
                "-p",
                "127.0.0.1::5432",
                "--mount",
                f"type=volume,src={volume},dst=/var/lib/postgresql/data",
                "--env-file",
                str(envfile),
                image,
            )
            .decode()
            .strip()
        )
        # Persist identity before any inspection failure; never clean failed resources.
        resources = {"postgres": {"id": identifier, "volume": volume, "label": run_id}}
        private_json(self.run / "private-rehearsal-resources.json", resources)
        record = json.loads(self.commands.docker("inspect", identifier))[0]
        port = owned_port(record, identifier, run_id, "5432/tcp")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                self.commands.docker("exec", identifier, "pg_isready", "-U", "kingphisher", timeout=5)
                break
            except Blocked:
                time.sleep(0.5)
        else:
            raise Blocked("rehearsal_database_readiness_deadline")
        globals_sql = (self.run / "checkpoint/globals.sql").read_bytes()
        if globals_sql.count(b"CREATE ROLE kingphisher;") != 1:
            raise Blocked("unexpected_cluster_globals")
        globals_sql = globals_sql.replace(b"CREATE ROLE kingphisher;", b"-- existing fresh bootstrap owner", 1)
        self.commands.docker(
            "exec",
            "-i",
            identifier,
            "psql",
            "-U",
            "kingphisher",
            "-d",
            "kingphisher",
            "-v",
            "ON_ERROR_STOP=1",
            input=globals_sql,
            timeout=90,
        )
        self.commands.docker(
            "exec",
            "-i",
            identifier,
            "pg_restore",
            "-U",
            "kingphisher",
            "-d",
            "kingphisher",
            "--exit-on-error",
            input=(self.run / "checkpoint/postgres.dump").read_bytes(),
            timeout=180,
        )
        clone = owner.set(host="127.0.0.1", port=port)
        clone_cfg = dict(cfg)
        for key, value in cfg.items():
            if "DATABASE_URL" in key:
                clone_cfg[key] = make_url(value).set(host="127.0.0.1", port=port).render_as_string(hide_password=False)
        before = summary(clone.render_as_string(hide_password=False))
        if before != checkpoint["database"]:
            raise Blocked("rehearsal_restored_database_differs")
        self._migrate(source, clone_cfg)
        after = summary(clone.render_as_string(hide_password=False))
        if after["schema"] != plan["schema_head"] or any(
            after["table_counts"].get(table) != count for table, count in before["table_counts"].items()
        ):
            raise Blocked("rehearsal_migration_changed_existing_rows")
        new = self._probe(source / ".venv/bin/python", source, clone_cfg, "private-new-code-proof.json")
        old = self._probe(NORMAL / ".venv/bin/python", NORMAL, clone_cfg, "private-old-code-proof.json")
        if not all(new["encrypted_entities"].get(name) == count for name, count in old["encrypted_entities"].items()):
            raise Blocked("old_new_key_identity_proofs_differ")
        # Both structural verification and a real Redis restart/load are required.
        redis_image = plan["normal_identity"]["containers"]["redis"]["image"]
        verifier = f"kp-development-upgrade-{run_id}-redis-verifier"
        self._resource_available(verifier)
        private_json(self.run / "private-redis-verifier-intent.json", {"name": verifier, "label": run_id})
        self.commands.docker(
            "run",
            "--name",
            verifier,
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--label",
            f"{LABEL}={run_id}",
            "--mount",
            f"type=bind,src={self.run / 'checkpoint'},dst=/checkpoint,readonly",
            "--entrypoint",
            "redis-check-rdb",
            redis_image,
            "/checkpoint/redis.rdb",
            timeout=90,
        )
        verifier_id = self.commands.docker("inspect", verifier, "--format", "{{.Id}}").decode().strip()
        resources["redis_verifier"] = {"id": verifier_id, "label": run_id}
        private_json(self.run / "private-redis-verifier-resource.json", resources["redis_verifier"])
        redis_name = f"kp-development-upgrade-{run_id}-redis"
        redis_volume = redis_name + "-data"
        self._resource_available(redis_name, redis_volume)
        private_json(
            self.run / "private-rehearsal-redis-intent.json",
            {"name": redis_name, "volume": redis_volume, "label": run_id},
        )
        password = secrets.token_hex(32)
        redis_config = self.run / "private-rehearsal-redis.conf"
        private_bytes(
            redis_config,
            (
                f'bind 0.0.0.0\nport 6379\nrequirepass {password}\nappendonly no\nsave ""\n'
                "dir /data\ndbfilename dump.rdb\n"
            ).encode(),
        )
        self.commands.docker("volume", "create", "--label", f"{LABEL}={run_id}", redis_volume)
        redis_id = (
            self.commands.docker(
                "run",
                "-d",
                "--name",
                redis_name,
                "--pull",
                "never",
                "--label",
                f"{LABEL}={run_id}",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "-p",
                "127.0.0.1::6379",
                "--mount",
                f"type=volume,src={redis_volume},dst=/data",
                "--mount",
                f"type=bind,src={self.run / 'checkpoint'},dst=/checkpoint,readonly",
                "--mount",
                f"type=bind,src={redis_config},dst=/private/redis.conf,readonly",
                "--entrypoint",
                "sh",
                redis_image,
                "-c",
                "cp /checkpoint/redis.rdb /data/dump.rdb && exec redis-server /private/redis.conf",
            )
            .decode()
            .strip()
        )
        resources["redis"] = {"id": redis_id, "volume": redis_volume, "label": run_id}
        private_json(self.run / "private-rehearsal-redis-resource.json", resources["redis"])
        redis_port = owned_port(json.loads(self.commands.docker("inspect", redis_id))[0], redis_id, run_id, "6379/tcp")
        restored = redis.Redis(
            host="127.0.0.1", port=redis_port, password=password, socket_timeout=3, socket_connect_timeout=3
        )
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    restored.ping()
                    if not restored.info("persistence")["loading"]:
                        break
                except redis.RedisError:
                    pass
                time.sleep(0.5)
            else:
                raise Blocked("restored_redis_readiness_deadline")
            compare_redis_inventory(
                read_json(self.run / "checkpoint/redis-inventory.json", max_bytes=128 * 1024 * 1024),
                redis_inventory(restored),
            )
        finally:
            restored.close()
        private_json(
            self.run / "rehearsal.json",
            {
                "passed": True,
                "database_schema": plan["schema_head"],
                "existing_rows_preserved": True,
                "old_new_ciphertext_and_audit_verified": True,
                "redis_rdb_integrity_verified": True,
                "redis_restore_verified": True,
                "resources_preserved": resources,
                "rollback": "read compatibility proved only; no automatic database rollback",
            },
        )

    def _resource_available(self, name: str, volume: str | None = None) -> None:
        # Listing exact names distinguishes absence from an engine/permission failure.
        if self.commands.docker("container", "ls", "-aq", "--filter", f"name=^/{name}$").strip():
            raise Blocked("rehearsal_container_name_collision")
        if volume and self.commands.docker("volume", "ls", "-q", "--filter", f"name=^{volume}$").strip():
            raise Blocked("rehearsal_volume_name_collision")

    def _migrate(self, source: Path, cfg: dict[str, str]) -> None:
        self.commands.run(
            [
                str(source / ".venv/bin/alembic"),
                "-c",
                str(source / "packages/database/alembic.ini"),
                "upgrade",
                self.plan["schema_head"],
            ],
            env=environment(dict(cfg, PGOPTIONS="-c lock_timeout=10000 -c statement_timeout=120000")),
            cwd=source,
            timeout=300,
        )

    def _verify_live_redis_checkpoint(self, cfg: dict[str, str]) -> None:
        expected = read_json(self.run / "checkpoint/redis-inventory.json", max_bytes=128 * 1024 * 1024)
        client = redis.Redis.from_url(cfg["REDIS_URL"], socket_timeout=5, socket_connect_timeout=3)
        try:
            compare_redis_inventory(expected, redis_inventory(client))
        finally:
            client.close()

    def cutover(self) -> None:
        plan, cfg = self.gate(stopped=True)
        checkpoint = self._checkpoint()
        phase_receipt(self.run / "rehearsal.json")
        review = phase_receipt(self.run / "reviewed-cutover.json")
        if (
            review.get("commit") != plan["commit"]
            or review.get("checkpoint_sha256") != digest(self.run / "checkpoint.json")
            or review.get("rehearsal_sha256") != digest(self.run / "rehearsal.json")
            or review.get("scope") != "additive_schema_and_resume_existing_native_runtime"
        ):
            raise Blocked("concrete_rehearsal_review_receipt_mismatch")
        if (self.run / "cutover.json").exists():
            raise Blocked("cutover_already_recorded")
        source = self._source(plan)
        dropin = canonical(Path(plan["dropin"]))
        if dropin.exists() or digest(source / ".env") != plan["private_config_sha256"]:
            raise Blocked("dropin_collision_or_private_configuration_drift")
        if summary(cfg["DATABASE_URL"]) != checkpoint["database"]:
            raise Blocked("normal_database_changed_after_checkpoint")
        current_queues = queue_snapshot(cfg["REDIS_URL"])
        require_send_queues_drained(current_queues)
        if any(
            current_queues[topic][kind] != stats[kind]
            for topic, stats in checkpoint["queue_stats"].items()
            for kind in ("ready", "processing", "delayed", "dead_letter")
        ):
            raise Blocked("reviewed_queue_counts_changed_after_checkpoint")
        self._verify_live_redis_checkpoint(cfg)
        self._migrate(source, cfg)
        migrated = summary(cfg["DATABASE_URL"])
        if migrated["schema"] != plan["schema_head"] or any(
            migrated["table_counts"].get(table) != count
            for table, count in checkpoint["database"]["table_counts"].items()
        ):
            raise Blocked("normal_migration_postcondition_failed_leave_stopped")
        dropin.parent.mkdir(mode=0o700, exist_ok=True)
        text_value = (
            f"[Service]\nWorkingDirectory={source}\nExecStart=\n"
            f"ExecStart=/usr/bin/env -i HOME=/home/builder "
            f"PATH={source / '.venv/bin'}:/home/builder/.local/bin:/usr/local/bin:/usr/bin:/bin "
            f"VIRTUAL_ENV={source / '.venv'} OPERATOR_API_ENV_FILE={source / '.env'} "
            "DOCKER_HOST=unix:///var/run/docker.sock "
            f"UV_PROJECT={source} UV_PROJECT_ENVIRONMENT={source / '.venv'} "
            f"{source / '.venv/bin/python'} {source / 'scripts/supervisor.py'}\n"
        )
        private_bytes(dropin, text_value.encode())
        private_json(self.run / "private-owned-dropin.json", {"path": str(dropin), "sha256": digest(dropin)})
        self.commands.run(["systemctl", "--user", "daemon-reload"])
        self.commands.run(["systemctl", "--user", "start", SERVICE], timeout=180)
        private_json(
            self.run / "cutover.json",
            {
                "passed": True,
                "schema": plan["schema_head"],
                "source": str(source),
                "database_rollback_performed": False,
                "original_unit_preserved": digest(UNIT) == plan["normal_identity"]["unit_sha256"],
            },
        )

    def verify(self) -> None:
        plan, _ = self.gate(stopped=False, switched=True)
        phase_receipt(self.run / "cutover.json")
        owned = read_json(self.run / "private-owned-dropin.json")
        if digest(Path(owned["path"])) != owned["sha256"]:
            raise Blocked("owned_dropin_changed")
        source = Path(plan["source"])
        cfg = configuration(source / ".env")
        proof = self._probe(source / ".venv/bin/python", source, cfg, "private-live-proof.json")
        if proof["schema"] != plan["schema_head"]:
            raise Blocked("live_schema_drift")
        port = int(cfg.get("OPERATOR_API_PORT", "8000"))
        tracking_port = int(cfg.get("TRACKING_API_PORT", "8001"))
        if not 1 <= port <= 65535 or not 1 <= tracking_port <= 65535:
            raise Blocked("invalid_existing_api_ports")
        deadline = time.monotonic() + 120
        with httpx.Client(timeout=3, trust_env=False, follow_redirects=False) as client:
            while time.monotonic() < deadline:
                try:
                    if all(
                        client.get(f"http://127.0.0.1:{value}/readyz").status_code == 200
                        for value in (port, tracking_port)
                    ):
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.5)
            else:
                raise Blocked("new_runtime_readiness_deadline")
            for name in ("index.html", "app.js", "styles.css"):
                response = client.get(f"http://127.0.0.1:{port}/console/{name}")
                if response.status_code != 200 or hashlib.sha256(response.content).hexdigest() != digest(
                    source / "apps/operator-ui/src/console" / name
                ):
                    raise Blocked("served_ui_does_not_match_qualified_source")
        names = [
            "operator-api",
            "tracking-api",
            *[
                f"worker-{role}"
                for role in (
                    "ingestion",
                    "generation",
                    "delivery",
                    "retention",
                    "mailbox",
                    "reply-mailbox",
                    "reminder",
                    "alert",
                    "directory",
                    "curation",
                    "audit-anchor",
                )
            ],
        ]
        for name in names:
            path = NORMAL / "data/run" / f"{name}.pid"
            raw = path.read_text().strip()
            if not re.fullmatch("[1-9][0-9]{0,8}", raw) or (Path("/proc") / raw / "cwd").resolve() != source:
                raise Blocked("child_pid_or_source_identity_mismatch")
            child_env = (Path("/proc") / raw / "environ").read_bytes().split(b"\0")
            if f"VIRTUAL_ENV={source / '.venv'}".encode() not in child_env:
                raise Blocked("child_environment_does_not_pin_new_venv")
        private_json(
            self.run / "verified.json",
            {
                "passed": True,
                "commit": plan["commit"],
                "ui_bytes_match": True,
                "api_ready": True,
                "native_children": len(names),
                "audit_and_ciphertext_verified": True,
                "normal_container_mount_identities_unchanged": True,
                "new_business_sends_exercised": False,
                "automatic_database_rollback": False,
            },
        )
