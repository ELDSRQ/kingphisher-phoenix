"""Hermetic guards: no normal services, databases, Docker or networks are used."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT_ROOT = Path(__file__).resolve().parents[1] / "scripts/operator/development-upgrade"
sys.path.insert(0, str(SCRIPT_ROOT))
from kp_dev_upgrade import coordinator, core, preflight  # noqa: E402 - import the dedicated script package
from kp_dev_upgrade.coordinator import Upgrade, archive_index, compare_redis_inventory, owned_port  # noqa: E402
from kp_dev_upgrade.core import Blocked, configuration, digest, private_bytes  # noqa: E402


class PrivateFakeCommands:
    def __init__(self, identity, unit):
        self.identity = identity
        self.unit_value = unit
        self.calls = []

    def normal_identity(self):
        return self.identity

    def unit(self):
        return self.unit_value

    def run(self, args, **kwargs):
        self.calls.append(args)
        assert args[:4] == ["/home/builder/.local/bin/uv", "sync", "--frozen", "--all-packages"]
        output = Path(args[-1]) / ".venv/bin/python"
        output.parent.mkdir(parents=True)
        output.write_text("synthetic interpreter placeholder")
        return b""

    def docker(self, *args, **kwargs):
        self.calls.append(list(args))
        raise AssertionError("Hermetic preservation test must never invoke Docker")


@pytest.fixture
def layout(tmp_path, monkeypatch):
    normal = tmp_path / "normal"
    normal.mkdir()
    (normal / "data").mkdir()
    (normal / "data/evidence").write_bytes(b"original evidence")
    (normal / ".venv").mkdir()
    (normal / ".venv/original").write_bytes(b"original environment")
    (normal / "docker-compose.override.yml").write_bytes(b"original override")
    config = {
        key: "postgresql+psycopg://kingphisher:private@127.0.0.1:5432/kingphisher"
        for key in (
            "DATABASE_URL",
            "AUDIT_DATABASE_URL",
            "OPERATOR_API_DATABASE_URL",
            "KP_WORKER_DATABASE_URL",
            "TRACKING_API_DATABASE_URL",
            "OPERATOR_API_AUDIT_DATABASE_URL",
            "KP_WORKER_AUDIT_DATABASE_URL",
        )
    }
    config.update(
        {
            key: "redis://:private@127.0.0.1:6379/0"
            for key in ("REDIS_URL", "OPERATOR_API_REDIS_URL", "KP_WORKER_REDIS_URL")
        }
    )
    private_bytes(normal / ".env", "\n".join(f"{key}={value}" for key, value in config.items()).encode())
    unit = tmp_path / "systemd/kp-supervisor.service"
    unit.parent.mkdir()
    unit.write_bytes(b"original service")
    runs = tmp_path / "qualification"
    runs.mkdir()
    releases = tmp_path / "releases"
    for module in (core, coordinator, preflight):
        for name, value in (("NORMAL", normal), ("UNIT", unit), ("RUNS", runs), ("RELEASES", releases)):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, value)
    monkeypatch.setattr(core, "source_head", lambda _: "0057_runtime_feature_grants")
    monkeypatch.setattr(coordinator, "bounds_preflight", lambda _: {"passed": True, "required_free_bytes": 8 * 1024**3})
    monkeypatch.setattr(coordinator.shutil, "disk_usage", lambda _: SimpleNamespace(free=16 * 1024**3))
    source = tmp_path / "qualified"
    (source / "scripts").mkdir(parents=True)
    for name in ("pyproject.toml", "uv.lock", "scripts/supervisor.py"):
        (source / name).write_bytes(b"qualified " + name.encode())
    commit = "a" * 40
    manifest = tmp_path / "qualified.json"
    private = {
        "commit": commit,
        "gates": {"ci": True, "images": True, "fullstack": True},
        "schema_head": "0057_runtime_feature_grants",
        "files": {str(path.relative_to(source)): digest(path) for path in source.rglob("*") if path.is_file()},
    }
    manifest.write_text(json.dumps(private))
    run = runs / "development-upgrade-20261106T190000Z-abc12345"
    commands = PrivateFakeCommands(
        {"engine": "pinned", "unit_sha256": digest(unit)},
        {
            "ActiveState": "active",
            "WorkingDirectory": str(normal),
            "FragmentPath": str(unit),
            "DropInPaths": "",
            "ControlGroup": "/user.slice/kp-supervisor.service",
        },
    )
    return SimpleNamespace(
        normal=normal,
        unit=unit,
        run=run,
        source=source,
        releases=releases,
        manifest=manifest,
        commit=commit,
        commands=commands,
        upgrade=Upgrade(run, commands),
    )


def prepare(layout):
    layout.upgrade.prepare(layout.source, layout.manifest, digest(layout.manifest), layout.commit)


def test_prepare_only_creates_versioned_copy_and_fresh_environment(layout):
    original = {path: path.read_bytes() for path in layout.normal.rglob("*") if path.is_file()}
    prepare(layout)
    plan = layout.upgrade.plan
    source = Path(plan["source"])
    assert source != layout.normal and source.parent.parent == layout.releases
    assert (source / "data").readlink() == layout.normal / "data"
    assert (source / ".venv/bin/python").is_file()
    assert (source / ".env").stat().st_mode & 0o777 == 0o600
    assert plan["schema_head"] == "0057_runtime_feature_grants"
    assert all(path.read_bytes() == value for path, value in original.items())
    assert layout.unit.read_bytes() == b"original service"
    assert len(layout.commands.calls) == 1 and layout.commands.calls[0][1:3] == ["sync", "--frozen"]


def add_qualified_executable(layout):
    name = "scripts/qualified-helper.sh"
    helper = layout.source / name
    helper.write_text("#!/bin/sh\nprintf 'qualified helper executed\\n'\n")
    helper.chmod(0o755)
    manifest = json.loads(layout.manifest.read_text())
    manifest["files"][name] = digest(helper)
    layout.manifest.write_text(json.dumps(manifest))
    return name


def test_prepared_operator_helper_remains_executable_and_private(layout):
    name = add_qualified_executable(layout)
    prepare(layout)
    copied = Path(layout.upgrade.plan["source"]) / name
    result = subprocess.run(  # noqa: S603 - fixed fixture verified by the source manifest
        [str(copied)], capture_output=True, text=True, check=True
    )
    assert result.stdout == "qualified helper executed\n"
    assert copied.stat().st_mode & 0o777 == 0o700
    assert (copied.parent.parent / "pyproject.toml").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("changed_mode", (0o600, 0o755))
def test_prepared_helper_mode_drift_is_refused_before_runtime_actions(layout, changed_mode):
    name = add_qualified_executable(layout)
    prepare(layout)
    plan = layout.upgrade.plan
    (Path(plan["source"]) / name).chmod(changed_mode)
    with pytest.raises(Blocked, match="prepared_source_mode_changed"):
        layout.upgrade._source(plan)
    assert len(layout.commands.calls) == 1  # Only the new environment sync ran.


@pytest.mark.parametrize("collision", ["run", "release"])
def test_prepare_collisions_preserve_every_existing_asset(layout, collision):
    target = layout.run if collision == "run" else layout.releases / f"{layout.commit}-20261106T190000Z-abc12345"
    target.mkdir(parents=True)
    (target / "existing").write_bytes(b"preserve me")
    before = {str(path): path.read_bytes() for path in target.rglob("*") if path.is_file()}
    with pytest.raises(Blocked, match="already_exists"):
        prepare(layout)
    assert {str(path): path.read_bytes() for path in target.rglob("*") if path.is_file()} == before
    assert layout.commands.calls == []


def test_bad_engine_identity_does_not_create_run_release_or_invoke_mutations(layout):
    def reject():
        raise Blocked("native_engine_identity_mismatch")

    layout.commands.normal_identity = reject
    with pytest.raises(Blocked, match="engine_identity"):
        prepare(layout)
    assert not layout.run.exists() and not layout.releases.exists()
    assert layout.commands.calls == []


def test_missing_active_cgroup_identity_blocks_prepare_before_any_write(layout):
    layout.commands.unit_value["ControlGroup"] = ""
    with pytest.raises(Blocked, match="cgroup_identity_missing"):
        prepare(layout)
    assert not layout.run.exists() and not layout.releases.exists() and layout.commands.calls == []


def test_unqualified_manifest_is_refused_before_writes(layout):
    manifest = json.loads(layout.manifest.read_text())
    manifest["gates"]["fullstack"] = False
    layout.manifest.write_text(json.dumps(manifest))
    with pytest.raises(Blocked, match="gates"):
        prepare(layout)
    assert not layout.run.exists() and not layout.releases.exists()
    assert layout.commands.calls == []


def test_changed_normal_identity_blocks_checkpoint_before_stop(layout):
    prepare(layout)
    layout.commands.calls.clear()
    layout.commands.identity = {"engine": "different"}
    with pytest.raises(Blocked, match="identity_changed"):
        layout.upgrade.checkpoint()
    assert layout.commands.calls == []
    assert not (layout.run / "checkpoint").exists()


def test_changed_prepared_source_blocks_checkpoint_before_stop(layout):
    prepare(layout)
    layout.commands.calls.clear()
    (Path(layout.upgrade.plan["source"]) / "scripts/supervisor.py").write_text("changed")
    with pytest.raises(Blocked, match="source_changed"):
        layout.upgrade.checkpoint()
    assert layout.commands.calls == [] and not (layout.run / "checkpoint").exists()


def test_cutover_requires_review_of_exact_private_checkpoint_and_rehearsal(layout, monkeypatch):
    prepare(layout)
    layout.commands.calls.clear()
    layout.commands.unit_value.update(ActiveState="inactive", MainPID="0")
    monkeypatch.setattr(layout.upgrade, "_checkpoint", lambda: {"passed": True})
    core.private_json(layout.run / "rehearsal.json", {"passed": True})
    core.private_json(
        layout.run / "reviewed-cutover.json",
        {
            "passed": True,
            "commit": "different-final-source",
            "checkpoint_sha256": "changed",
            "rehearsal_sha256": "changed",
            "scope": "additive_schema_and_resume_existing_native_runtime",
        },
    )
    with pytest.raises(Blocked, match="receipt_mismatch"):
        layout.upgrade.cutover()
    assert layout.commands.calls == []
    assert not Path(layout.upgrade.plan["dropin"]).exists()


def test_native_engine_guard_has_no_context_fallback_or_runtime_mutations(monkeypatch):
    monkeypatch.setattr(core.platform, "system", lambda: "Linux")
    monkeypatch.setattr(core.platform, "release", lambda: "6.6-microsoft-standard-WSL2")
    monkeypatch.setattr(core.socket, "gethostname", lambda: core.HOST)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)

    class WrongEngine(core.Commands):
        def __init__(self):
            super().__init__()
            self.calls = []

        def run(self, args, **kwargs):
            self.calls.append(args)
            return json.dumps({"ID": "foreign-engine", "OSType": "linux", "Architecture": "amd64"}).encode()

    commands = WrongEngine()
    with pytest.raises(Blocked, match="engine_identity_mismatch"):
        commands.normal_identity()
    assert len(commands.calls) == 1
    assert commands.calls[0][:4] == ["docker", "--host", "unix:///var/run/docker.sock", "info"]


@pytest.mark.parametrize("captured", ["private-before-service.json", "private-before-stop.json"])
def test_cleared_systemd_cgroup_still_checks_captured_processes(layout, monkeypatch, captured):
    prepare(layout)
    layout.commands.calls.clear()
    layout.commands.unit_value.update(ActiveState="inactive", MainPID="0", ControlGroup="")
    group = "/user.slice/kp-supervisor.service"
    if captured == "private-before-stop.json":
        core.private_json(layout.run / captured, {"service": {"ControlGroup": group}})
        (layout.run / "private-before-service.json").write_text(json.dumps({"ControlGroup": ""}))
    root = layout.run / "fake-cgroups"
    member = root / group.lstrip("/") / "surviving-child/cgroup.procs"
    member.parent.mkdir(parents=True)
    member.write_text("1234\n")
    monkeypatch.setattr(coordinator, "CGROUP_ROOT", root)
    with pytest.raises(Blocked, match="children_still_running"):
        layout.upgrade.gate(stopped=True)
    assert layout.commands.calls == []
    member.write_text("")
    layout.upgrade.gate(stopped=True)


def test_equal_queue_counts_with_changed_maintenance_payload_block_cutover_before_migration(layout, monkeypatch):
    prepare(layout)
    layout.commands.calls.clear()
    layout.commands.unit_value.update(ActiveState="inactive", MainPID="0", ControlGroup="")
    snapshot = {
        topic: {kind: 0 for kind in ("ready", "processing", "delayed", "dead_letter")}
        for topic in preflight.DEFAULT_QUEUE_TOPICS
    }
    snapshot["retention"]["ready"] = 1
    database = {"schema": core.OLD_SCHEMA, "table_counts": {"synthetic": 1}}
    checkpoint = {"passed": True, "database": database, "queue_stats": snapshot}
    core.private_json(layout.run / "checkpoint.json", checkpoint)
    core.private_json(layout.run / "rehearsal.json", {"passed": True})
    core.private_json(
        layout.run / "reviewed-cutover.json",
        {
            "passed": True,
            "commit": layout.commit,
            "checkpoint_sha256": digest(layout.run / "checkpoint.json"),
            "rehearsal_sha256": digest(layout.run / "rehearsal.json"),
            "scope": "additive_schema_and_resume_existing_native_runtime",
        },
    )
    (layout.run / "checkpoint").mkdir()
    core.private_json(
        layout.run / "checkpoint/redis-inventory.json",
        {"maintenance-key": {"sha256": "reviewed-content", "expires_ms": None}},
    )
    monkeypatch.setattr(layout.upgrade, "_checkpoint", lambda: checkpoint)
    monkeypatch.setattr(coordinator, "summary", lambda _: database)
    monkeypatch.setattr(coordinator, "queue_snapshot", lambda _: snapshot)
    monkeypatch.setattr(coordinator.redis.Redis, "from_url", lambda *_, **__: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(
        coordinator,
        "redis_inventory",
        lambda _: {"maintenance-key": {"sha256": "different-content", "expires_ms": None}},
    )
    monkeypatch.setattr(layout.upgrade, "_migrate", lambda *_: pytest.fail("migration must not run"))
    with pytest.raises(Blocked, match="redis_restore_value_differs"):
        layout.upgrade.cutover()
    assert layout.commands.calls == [] and not Path(layout.upgrade.plan["dropin"]).exists()


def test_existing_rehearsal_volume_is_never_reused_even_if_container_is_absent(layout):
    class ExistingVolume:
        def __init__(self):
            self.calls = []

        def docker(self, *args):
            self.calls.append(args)
            return b"" if args[:2] == ("container", "ls") else b"existing-volume\n"

    commands = ExistingVolume()
    layout.upgrade.commands = commands
    with pytest.raises(Blocked, match="volume_name_collision"):
        layout.upgrade._resource_available("new-container", "existing-volume")
    assert all(args[1] == "ls" for args in commands.calls)


def test_plan_target_rebinding_is_rejected(layout):
    prepare(layout)
    plan = json.loads((layout.run / "plan.json").read_text())
    plan["source"] = str(layout.normal)
    (layout.run / "plan.json").write_text(json.dumps(plan))
    with pytest.raises(Blocked, match="target_mismatch"):
        layout.upgrade.gate(stopped=False)


@pytest.mark.parametrize(
    "extra",
    [
        "KP_WORKER_DELIVERY_DATABASE_URL=postgresql://private:private@outside.test/kingphisher",
        "KP_WORKER_REDIS_URL=redis://127.0.0.1:51459/0",
        "PYTHONPATH=/outside",
        "PATH=/outside",
        "DOCKER_HOST=unix:///outside.sock",
        "DOCKER_CONTEXT=desktop-linux",
        "AZURE_GRAPH_CERT_PATH=/outside/private.pem",
        "KP_WORKER_DATABASE_URL_DELIVERY=postgresql://private:private@127.0.0.1:51459/kingphisher",
        "kp_worker_database_url_retention=postgresql://private:private@outside.test:5432/kingphisher",
        "PGPORT=51459",
        "PGHOST=outside.test",
        "PGSERVICE=other-cluster",
        "database_url=postgresql://private:private@127.0.0.1:5432/kingphisher",
    ],
)
def test_configuration_rejects_hidden_endpoint_or_code_resolution_changes(layout, extra):
    with (layout.normal / ".env").open("a") as stream:
        stream.write("\n" + extra + "\n")
    with pytest.raises(Blocked):
        configuration(layout.normal / ".env")


def test_ambient_libpq_override_is_refused_before_any_preflight_or_write(layout, monkeypatch):
    monkeypatch.setenv("PGPORT", "51459")
    with pytest.raises(Blocked, match="ambient_libpq"):
        prepare(layout)
    assert not layout.run.exists() and layout.commands.calls == []
    with pytest.raises(Blocked, match="ambient_libpq"):
        coordinator.summary("postgresql://private:private@127.0.0.1/kingphisher")
    with pytest.raises(Blocked, match="ambient_libpq"):
        preflight.bounds_preflight({})


def test_private_evidence_never_overwrites_and_refuses_symlink_parent(tmp_path):
    path = tmp_path / "private.json"
    private_bytes(path, b"original")
    with pytest.raises(FileExistsError):
        private_bytes(path, b"replacement")
    assert path.read_bytes() == b"original" and path.stat().st_mode & 0o777 == 0o600
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(Blocked, match="noncanonical"):
        private_bytes(tmp_path / "link/other.json", b"replacement")
    assert not (tmp_path / "other.json").exists()


def container_record():
    return {
        "Id": "owned-id",
        "Config": {"Labels": {core.LABEL: "owned-run"}},
        "State": {"Running": True},
        "NetworkSettings": {"Ports": {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "55432"}]}},
    }


@pytest.mark.parametrize("mutation", ["null", "missing", "wildcard", "extra", "stopped", "foreign", "preserved_port"])
def test_rehearsal_refuses_unsafe_mapping_or_ownership(mutation):
    record = container_record()
    if mutation == "null":
        record["NetworkSettings"]["Ports"] = None
    elif mutation == "missing":
        record["NetworkSettings"]["Ports"] = {}
    elif mutation == "wildcard":
        record["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostIp"] = "0.0.0.0"  # noqa: S104 - rejected input
    elif mutation == "extra":
        record["NetworkSettings"]["Ports"]["9999/tcp"] = None
    elif mutation == "stopped":
        record["State"]["Running"] = False
    elif mutation == "foreign":
        record["Config"]["Labels"][core.LABEL] = "other-run"
    else:
        record["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"] = "51459"
    with pytest.raises(Blocked):
        owned_port(record, "owned-id", "owned-run", "5432/tcp")


def test_owned_loopback_mapping_is_accepted():
    assert owned_port(container_record(), "owned-id", "owned-run", "5432/tcp") == 55432


def test_restore_keeps_all_persistent_values_and_allows_only_expired_keys(monkeypatch):
    monkeypatch.setattr(coordinator.time, "time", lambda: 100)
    stable = {"sha256": "stable", "expires_ms": None}
    expired = {"sha256": "expired", "expires_ms": 99000}
    compare_redis_inventory({"stable": stable, "expired": expired}, {"stable": stable})
    with pytest.raises(Blocked, match="missing_unexpired"):
        compare_redis_inventory({"stable": stable}, {})
    with pytest.raises(Blocked, match="value_differs"):
        compare_redis_inventory({"stable": stable}, {"stable": {**stable, "sha256": "changed"}})
    with pytest.raises(Blocked, match="unexpected_keys"):
        compare_redis_inventory({}, {"stable": stable})


def test_observed_150k_redis_state_is_inventoried_with_bounded_pipeline_batches():
    class FakePipeline:
        def __init__(self, client):
            self.client = client
            self.operations = []

        def type(self, key):
            self.operations.append(("type", key))

        def get(self, key):
            self.operations.append(("get", key))

        def pttl(self, key):
            self.operations.append(("pttl", key))

        def execute(self):
            assert len(self.operations) <= 1000
            self.client.batches += 1
            return [
                {"type": b"string", "get": b"durable-value", "pttl": -1}[operation] for operation, _ in self.operations
            ]

    class ObservedRedis:
        def __init__(self):
            self.batches = 0

        def scan(self, cursor, count):
            assert count == 500
            end = min(cursor + count, 150042)
            return (0 if end == 150042 else end), [f"synthetic-{index}".encode() for index in range(cursor, end)]

        def pipeline(self, transaction):
            assert transaction is False
            return FakePipeline(self)

    client = ObservedRedis()
    inventory = coordinator.redis_inventory(client)
    assert len(inventory) == 150042 and client.batches == 602
    assert all(value["expires_ms"] is None for value in inventory.values())
    assert all(len(name) == 64 and "synthetic" not in name for name in inventory)


def test_logical_hash_ignores_unordered_encoding_but_binds_types_order_and_duplicate_stream_fields():
    logical = coordinator.logical_redis_digest
    assert logical("hash", {b"a": b"1", b"b": b"2"}) == logical("hash", {b"b": b"2", b"a": b"1"})
    assert logical("set", {b"a", b"b"}) == logical("set", {b"b", b"a"})
    assert logical("list", [b"a", b"b"]) != logical("list", [b"b", b"a"])
    assert logical("string", b"ab") != logical("list", [b"a", b"b"])
    assert logical("stream", [[b"1-0", [b"key", b"first", b"key", b"last"]]]) != logical(
        "stream", [[b"1-0", [b"key", b"changed", b"key", b"last"]]]
    )


@pytest.mark.parametrize("topic", ["deliver", "reply-mailbox", "alert"])
@pytest.mark.parametrize("kind", ["ready", "processing", "delayed"])
def test_nondrained_sensitive_queue_is_refused_without_replaying_or_clearing(topic, kind):
    snapshot = {
        name: {field: 0 for field in ("ready", "processing", "delayed", "dead_letter")}
        for name in preflight.DEFAULT_QUEUE_TOPICS
    }
    snapshot[topic][kind] = 1
    with pytest.raises(Blocked, match="not_drained"):
        preflight.require_send_queues_drained(snapshot)
    assert snapshot[topic][kind] == 1


def test_maintenance_and_dlq_are_preserved_and_reported_without_forcing_replay():
    snapshot = {
        name: {field: 0 for field in ("ready", "processing", "delayed", "dead_letter")}
        for name in preflight.DEFAULT_QUEUE_TOPICS
    }
    snapshot["retention"]["ready"] = 1
    snapshot["deliver"]["dead_letter"] = 3
    preflight.require_send_queues_drained(snapshot)
    assert snapshot["retention"]["ready"] == 1 and snapshot["deliver"]["dead_letter"] == 3


def test_unsupported_archive_layout_is_refused_during_prepare_before_new_files(layout):
    (layout.normal / "data/external-key").symlink_to(layout.normal / ".env")
    with pytest.raises(Blocked, match="link_or_special"):
        preflight.bounds_preflight(configuration(layout.normal / ".env"))
    assert not layout.run.exists() and layout.commands.calls == []


def test_read_only_bounds_refuse_predictable_encrypted_row_and_disk_failures(layout, monkeypatch):
    from sqlalchemy import Column, Integer, MetaData, Table

    encrypted_table = Table(
        "synthetic_encrypted", MetaData(), Column("id", Integer), Column("mailbox", preflight.CipherText())
    )
    monkeypatch.setattr(
        preflight,
        "Base",
        SimpleNamespace(
            registry=SimpleNamespace(
                mappers=[SimpleNamespace(local_table=encrypted_table, columns=list(encrypted_table.columns))]
            )
        ),
    )
    monkeypatch.setattr(
        preflight, "inspect", lambda _: SimpleNamespace(get_table_names=lambda **_: [encrypted_table.name])
    )

    class CountsOnlyConnection:
        def __init__(self, encrypted_rows):
            self.encrypted_rows = encrypted_rows

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def scalar(self, statement):
            return 100000 if "pg_database_size" in str(statement) else self.encrypted_rows

    class CountsOnlyEngine:
        def __init__(self, rows):
            self.rows = rows

        def connect(self):
            return CountsOnlyConnection(self.rows)

        def dispose(self):
            pass

    class MetadataOnlyRedis:
        def dbsize(self):
            return 150042

        def info(self, kind):
            assert kind == "memory"
            return {"used_memory": 32758112}

        def close(self):
            pass

        def module_list(self):
            return []

    monkeypatch.setattr(preflight.redis.Redis, "from_url", lambda *_, **__: MetadataOnlyRedis())
    monkeypatch.setattr(preflight, "create_engine", lambda *_, **__: CountsOnlyEngine(10001))
    with pytest.raises(Blocked, match="encrypted_entity_preflight_bound"):
        preflight.bounds_preflight(configuration(layout.normal / ".env"))
    monkeypatch.setattr(preflight, "create_engine", lambda *_, **__: CountsOnlyEngine(32))
    monkeypatch.setattr(preflight.os, "statvfs", lambda _: SimpleNamespace(f_bavail=1, f_frsize=4096))
    with pytest.raises(Blocked, match="computed_checkpoint_headroom"):
        preflight.bounds_preflight(configuration(layout.normal / ".env"))
    monkeypatch.setattr(preflight.os, "statvfs", lambda _: SimpleNamespace(f_bavail=1000000000, f_frsize=4096))
    result = preflight.bounds_preflight(configuration(layout.normal / ".env"))
    assert result["redis_keys"] == 150042
    assert result["required_free_bytes"] > 8 * 1024**3
    assert not layout.run.exists() and layout.commands.calls == []


def test_queue_snapshot_calls_only_stats_for_all_topics_and_closes_client(monkeypatch):
    calls = []

    class StatsOnlyQueue:
        def __init__(self, url):
            assert url.endswith("?socket_timeout=5&socket_connect_timeout=3")

        def queue_stats(self, topic):
            calls.append(topic)
            return {"ready": 0, "processing": 0, "delayed": 0, "dead_letter": 2}

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(preflight, "JobQueue", StatsOnlyQueue)
    result = preflight.queue_snapshot("redis://127.0.0.1:6379/0")
    assert calls == [*preflight.DEFAULT_QUEUE_TOPICS, "closed"]
    assert len(result) == len(preflight.DEFAULT_QUEUE_TOPICS)
    assert all(value["dead_letter"] == 2 for value in result.values())


def test_backup_inventory_proves_private_config_data_and_unit_and_rejects_links(tmp_path):
    archive_path = tmp_path / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        for name in (".env", "data/audit-anchors/v2/witness.json", "unit/kp-supervisor.service"):
            member = tarfile.TarInfo(name)
            member.size = 8
            archive.addfile(member, io.BytesIO(b"preserve"))
    assert set(archive_index(archive_path)) == {
        ".env",
        "data/audit-anchors/v2/witness.json",
        "unit/kp-supervisor.service",
    }
    with tarfile.open(archive_path, "a") as archive:
        link = tarfile.TarInfo("data/key-link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/private/key"
        archive.addfile(link)
    with pytest.raises(Blocked, match="unsafe"):
        archive_index(archive_path)


def test_default_cli_does_not_even_probe_target_or_create_requested_directory(tmp_path):
    run = tmp_path / "would-be-created"
    process = subprocess.run(  # noqa: S603 - fixed checked-in script and isolated path
        [sys.executable, str(SCRIPT_ROOT / "run.py"), "cutover", "--run", str(run)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": os.environ["PATH"]},
    )
    assert process.returncode == 0 and "no changes performed" in process.stdout
    assert not run.exists()
