"""Meaningful restore-path tests with synthetic private files and command doubles."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parents[1] / "scripts/operator/recovery-qualification"
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("offhost_target", HERE / "target_restore.py")
assert SPEC is not None and SPEC.loader is not None
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)


def directory(path):
    path.mkdir(mode=0o700)
    return path


def private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def source_tree(tmp_path):
    root = directory(tmp_path / "source")
    (root / "scripts").mkdir()
    manifest = {}
    for name in ("scripts/install.sh", "scripts/verify_install.sh", "docker-compose.yml"):
        raw = ("synthetic committed " + name + "\n").encode()
        path = root / name
        path.write_bytes(raw)
        path.chmod(0o700 if name.endswith(".sh") else 0o600)
        manifest[name] = {
            "mode": "100755" if name.endswith(".sh") else "100644",
            "blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest(),
        }
    return root, manifest


def bare_target(tmp_path):
    value = object.__new__(target.Target)
    value.root = directory(tmp_path / "source")
    value.output = directory(tmp_path / "evidence")
    value.snapshot = directory(value.output / "snapshot")
    value.deadline = time.time() + 900
    value.run_id = "synthetic-run"
    value.suffix = "abcdef0123456789"
    value.env = {"DOCKER_HOST": target.SOCKET}
    value.user = SimpleNamespace(pw_name="kpqual", pw_uid=os.geteuid(), pw_gid=os.getegid())
    value.engine = {"id": "synthetic-engine", "root": str(tmp_path / "docker"), "socket": target.SOCKET}
    value.request = {"expected_hostname": "synthetic-host", "expected_vm_id": "/synthetic/target"}
    value.containers = {"postgres": "a" * 64, "redis": "b" * 64}
    value.model = {
        "services": {
            "postgres": {
                "image": "postgres@sha256:" + "1" * 64,
                "environment": {
                    "POSTGRES_USER": "kingphisher",
                    "POSTGRES_DB": "kingphisher",
                    "POSTGRES_PASSWORD": "synthetic-password",
                },
            },
            "redis": {"image": "redis@sha256:" + "2" * 64},
        }
    }
    return value


@pytest.mark.parametrize("ambient_uv", [False, True])
def test_actual_target_environment_resolves_the_pinned_bootstrap_uv(tmp_path, monkeypatch, ambient_uv):
    root, manifest = source_tree(tmp_path)
    home = directory(tmp_path / "app-home")
    app_uid = os.geteuid() or 1000
    if os.geteuid() == 0:
        os.chown(home, app_uid, os.getegid())
    user = SimpleNamespace(pw_name="kpqual", pw_uid=app_uid, pw_gid=os.getegid(), pw_dir=str(home))
    monkeypatch.setattr(target.pwd, "getpwnam", lambda name: user)
    qualified = tmp_path / "tools/uv-venv/bin/uv"
    qualified.parent.mkdir(mode=0o700, parents=True)
    qualified.write_text("#!/bin/sh\nprintf 'uv 0.12.7\\n'\n")
    qualified.chmod(0o755)
    ambient = directory(tmp_path / "ambient-bin")
    if ambient_uv:
        (ambient / "uv").write_text("#!/bin/sh\nprintf 'unqualified ambient executable\\n'\n")
        (ambient / "uv").chmod(0o755)
    monkeypatch.setenv("PATH", str(ambient))
    request = {
        "schema": target.TARGET_REQUEST_SCHEMA,
        "scope": "synthetic-qualification",
        "deadline": time.time() + 300,
        "source_root": str(root),
        "output": str(tmp_path / "evidence"),
        "application": {"runtime_commit": target.RUNTIME_COMMIT, "bundle_commit": "a" * 40},
        "run_id": "actual-uv-invocation",
        "expected_engine": {"socket": target.SOCKET},
        "app_user": "kpqual",
        "source_deallocated": {"verified": True, "receipt_sha256": "b" * 64},
        "source_git_manifest": manifest,
    }
    value = target.Target(request)
    invoked = subprocess.run(
        ["/bin/sh", "-c", "uv --version"], env=value.env, capture_output=True, timeout=5, check=False
    )
    assert invoked.returncode == 0, invoked.stderr
    assert invoked.stdout == b"uv 0.12.7\n"
    assert value.env["PATH"].split(":")[0] == str(qualified.parent)


def test_default_cli_plan_does_not_read_request_or_call_commands(monkeypatch, capsys):
    def forbidden(*_args, **_kwargs):
        pytest.fail("Plan invoked an operation")

    monkeypatch.setattr(target, "command", forbidden)
    monkeypatch.setattr(target, "read_json", forbidden)
    monkeypatch.setattr(target, "restore", forbidden)
    assert target.main(["--request", "/nonexistent/private-request.json"]) == 0
    assert json.loads(capsys.readouterr().out)["commands"] == 0


@pytest.mark.parametrize("change", ["bytes", "executable", "extra", "missing"])
def test_source_git_binding_rejects_drift_before_execution(tmp_path, change):
    root, manifest = source_tree(tmp_path)
    target.verify_source(root, manifest)
    if change == "bytes":
        (root / "scripts/install.sh").write_text("unqualified source")
    elif change == "executable":
        (root / "scripts/install.sh").chmod(0o600)
    elif change == "extra":
        (root / "unqualified.py").write_text("unqualified module")
    else:
        (root / "scripts/install.sh").rename(root / "scripts/moved.sh")
    with pytest.raises(target.RecoveryError, match="source_"):
        target.verify_source(root, manifest)


def test_config_retarget_changes_only_source_root_path_purposes():
    raw = (
        b"TOKEN=/old/source/token\nKEY_PATH='/old/source/data/key'\n"
        b"OTHER_PATH=/old/source-sibling/key\nKEY_DIR=data/keys\n"
    )
    result, changed = target.retarget_config(raw, "/old/source", "/new/source")
    assert (
        result == b"TOKEN=/old/source/token\nKEY_PATH='/new/source/data/key'\n"
        b"OTHER_PATH=/old/source-sibling/key\nKEY_DIR=data/keys\n"
    )
    assert changed == ["KEY_PATH"]


def test_globals_omits_only_exact_bootstrap_create_keeps_passwords_grants_and_other_roles():
    raw = (
        b"-- globals\nCREATE ROLE kingphisher;\nALTER ROLE kingphisher WITH SUPERUSER PASSWORD 'synthetic';\n"
        b"CREATE ROLE audit_writer;\nGRANT audit_writer TO kingphisher;\n"
    )
    result = target.globals_without_bootstrap_role(raw)
    assert result == raw.replace(b"CREATE ROLE kingphisher;\n", b"", 1)
    assert b"PASSWORD 'synthetic'" in result and b"CREATE ROLE audit_writer;" in result


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"CREATE ROLE kingphisher;\nCREATE ROLE kingphisher;\n",
        b"-- CREATE ROLE kingphisher;\n",
        b"CREATE ROLE kingphisher;\r\n",
    ],
)
def test_globals_ambiguous_bootstrap_is_refused(raw):
    with pytest.raises(target.RecoveryError, match="bootstrap_role"):
        target.globals_without_bootstrap_role(raw)


@pytest.mark.parametrize(
    "after,reason",
    [
        ({}, "missing"),
        ({"key": {"sha256": "wrong", "expires_ms": None}}, "value"),
        ({"key": {"sha256": "same", "expires_ms": 10000}}, "expiry_kind"),
        ({"key": {"sha256": "same", "expires_ms": None}, "extra": {}}, "unexpected"),
    ],
)
def test_redis_inventory_must_preserve_persistent_values(after, reason):
    with pytest.raises(target.RecoveryError, match=reason):
        target.compare_redis({"key": {"sha256": "same", "expires_ms": None}}, after, now_ms=1000)


def test_redis_expired_keys_may_expire_but_unexpired_expiry_must_match():
    target.compare_redis({"old": {"sha256": "same", "expires_ms": 100}}, {}, now_ms=1000)
    with pytest.raises(target.RecoveryError, match="expiry_drift"):
        target.compare_redis(
            {"key": {"sha256": "same", "expires_ms": 10000}},
            {"key": {"sha256": "same", "expires_ms": 20000}},
            now_ms=1000,
        )


def test_fresh_engine_rejects_existing_containers_before_decrypt(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    monkeypatch.setattr(target.socket, "gethostname", lambda: "synthetic-host")
    monkeypatch.setattr(value, "call", lambda *_a, **_kw: b"/synthetic/target")
    calls = []

    def docker(*args, **_kwargs):
        calls.append(args)
        if args[0] == "info":
            return json.dumps(
                {
                    "ID": value.engine["id"],
                    "DockerRootDir": value.engine["root"],
                    "Architecture": "x86_64",
                    "OSType": "linux",
                }
            ).encode()
        return b"existing-container"

    monkeypatch.setattr(value, "docker", docker)
    with pytest.raises(target.RecoveryError, match="existing_containers"):
        value.fresh()
    assert not any(args[0] in {"create", "run", "start"} for args in calls)


def test_actual_pg_restore_protocol_preserves_all_globals_and_stops_helper_before_canonical(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    globals_raw = b"CREATE ROLE kingphisher;\nALTER ROLE kingphisher PASSWORD 'synthetic';\nCREATE ROLE audit_owner;\n"
    private(value.snapshot / "globals.sql", globals_raw)
    private(value.snapshot / "postgres.dump", b"PGDMP synthetic")
    helper = "c" * 64
    monkeypatch.setattr(value, "helper", lambda *_a, **_kw: helper)
    events = []

    def pg(_identifier, sql):
        if sql == "SELECT 1":
            return 1
        return ["kingphisher"] if "pg_roles" in sql else 0

    def docker(*args, **kwargs):
        events.append((args, kwargs))
        if args[0] == "inspect":
            return b'[{"State":{"Running":false}}]'
        return b""

    monkeypatch.setattr(value, "pg_json", pg)
    monkeypatch.setattr(value, "docker", docker)
    value.restore_postgres("new-postgres-volume")
    sql = next(kwargs["data"] for args, kwargs in events if args[0] == "exec" and "psql" in args)
    assert sql == globals_raw.replace(b"CREATE ROLE kingphisher;\n", b"")
    restore_args = next(args for args, _kwargs in events if "pg_restore" in args)
    assert "--exit-on-error" in restore_args and "--single-transaction" in restore_args
    operations = [args for args, _kwargs in events]
    assert operations.index(("stop", "--time", "30", helper)) < operations.index(
        ("start", value.containers["postgres"])
    )
    assert all(not set(args).intersection({"rm", "down", "prune", "--clean", "--if-exists"}) for args in operations)


def test_pg_nonempty_database_refuses_before_globals_or_restore(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    monkeypatch.setattr(value, "helper", lambda *_a, **_kw: "c" * 64)
    monkeypatch.setattr(
        value, "pg_json", lambda _id, sql: 1 if sql == "SELECT 1" else ["kingphisher"] if "pg_roles" in sql else 1
    )
    calls = []
    monkeypatch.setattr(value, "docker", lambda *a, **_kw: calls.append(a) or b"")
    with pytest.raises(target.RecoveryError, match="database_not_empty"):
        value.restore_postgres("new-volume")
    assert not any("pg_restore" in args or "psql" in args for args in calls)


def test_actual_redis_materialization_stops_retained_helper_before_canonical_start(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    private(value.snapshot / "redis.rdb", b"synthetic-rdb")
    ids = {"redis-permissions": "c" * 64, "redis-materializer": "d" * 64}
    monkeypatch.setattr(value, "helper", lambda kind, *_a, **_kw: ids[kind])
    calls = []

    def docker(*args, **_kwargs):
        calls.append(args)
        if args[0] == "inspect":
            return b'[{"State":{"Running":false,"ExitCode":0}}]'
        return b""

    def redis(_id, *args):
        calls.append(("redis-cli", *args))
        if args == ("PING",):
            return b"PONG\n"
        if args[:2] == ("CONFIG", "SET"):
            return b"OK\n"
        return b"aof_enabled:1\r\naof_rewrite_in_progress:0\r\naof_last_bgrewrite_status:ok\r\naof_current_size:200\r\n"

    monkeypatch.setattr(value, "docker", docker)
    monkeypatch.setattr(value, "redis_cli", redis)
    value.restore_redis("new-redis-volume")
    assert calls.index(("stop", "--time", "30", ids["redis-materializer"])) < calls.index(
        ("start", value.containers["redis"])
    )
    assert ("redis-cli", "CONFIG", "SET", "appendonly", "yes") in calls
    assert all(not set(args).intersection({"rm", "down", "prune", "--rm"}) for args in calls)


def test_restore_data_mismatch_blocks_all_application_startup(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    stages = []
    for name in (
        "fresh",
        "prepare_source",
        "decrypt",
        "restore_files",
        "configure_compose",
        "restore_postgres",
        "restore_redis",
    ):
        monkeypatch.setattr(value, name, lambda *_a, stage=name: stages.append(stage))
    monkeypatch.setattr(value, "call", lambda *_a, **_kw: b"")
    monkeypatch.setattr(value, "compose", lambda *_a, **_kw: b"")
    monkeypatch.setattr(value, "canonical_container", lambda service: ("e" * 64, service + "_data"))

    def refuse():
        raise target.RecoveryError("restored_database_counts_audit_ciphertext_or_sentinel_drift")

    monkeypatch.setattr(value, "verify_restored_state", refuse)
    monkeypatch.setattr(value, "install", lambda: pytest.fail("Invalid data started application"))
    monkeypatch.setattr(value, "runtime_proof", lambda: pytest.fail("Invalid data claimed runtime proof"))
    with pytest.raises(target.RecoveryError, match="restored_database"):
        value.run()
    assert stages == [
        "fresh",
        "prepare_source",
        "decrypt",
        "restore_files",
        "configure_compose",
        "restore_postgres",
        "restore_redis",
    ]
    assert not (value.output / "startup-authorized.json").exists()
    assert not (value.output / "result.json").exists()


def test_private_state_writes_are_no_clobber_and_private(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "state"
    target.write_private_state(path, b"preserved", executable=False, app_uid=os.geteuid())
    with pytest.raises(FileExistsError):
        target.write_private_state(path, b"replacement", executable=False, app_uid=os.geteuid())
    assert path.read_bytes() == b"preserved" and path.stat().st_mode & 0o777 == 0o600


def test_every_embedded_probe_is_valid_python():
    for script in (target.CONFIG_PROBE, target.OVERRIDE_PROBE, target.MAINTENANCE_PROBE, target.AUDIT_PREFIX_PROBE):
        compile(script, "restore-probe", "exec")


def test_restore_files_preserves_keys_and_retargets_only_new_state(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    old = "/srv/old-synthetic-source"
    config = {"POSTGRES_PASSWORD": "synthetic-password", "SECRET_KEY": "synthetic-key", "KEY_PATH": old + "/data/key"}
    raw_env = (
        b"POSTGRES_PASSWORD=synthetic-password\nSECRET_KEY=synthetic-key\nKEY_PATH=/srv/old-synthetic-source/data/key\n"
    )
    files = {
        "state/.env": raw_env,
        "state/data/key": b"protected-purpose-key",
        "state/data/recovery/sentinel": b"acknowledged-synthetic-file",
    }
    metadata = {}
    for name, raw in files.items():
        path = value.snapshot / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        private(path, raw)
        metadata[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": "0600"}
    value.manifest = {
        "application": {"source_root": old},
        "files": metadata,
        "data": {
            "protected_purposes": target.purpose_fingerprints(config),
            "file_sentinel": {
                "path": "data/recovery/sentinel",
                "value": "acknowledged-synthetic-file",
                "sha256": hashlib.sha256(files["state/data/recovery/sentinel"]).hexdigest(),
            },
        },
    }
    monkeypatch.setattr(value, "chown_new_source", lambda: None)
    monkeypatch.setattr(value, "call", lambda *_a, **_kw: b"")
    monkeypatch.setattr(value, "app_python", lambda *_a, **_kw: config | {"KEY_PATH": str(value.root / "data/key")})
    value.restore_files()
    assert (value.root / "data/key").read_bytes() == files["state/data/key"]
    assert b"SECRET_KEY=synthetic-key" in (value.root / ".env").read_bytes()
    assert str(value.root / "data/key").encode() in (value.root / ".env").read_bytes()
    assert value.restored_files["data/key"]["source_sha256"] == value.restored_files["data/key"]["restored_sha256"]


@pytest.mark.parametrize("change", ["database", "redis", "maintenance", "files"])
def test_real_pre_startup_verification_refuses_each_data_gate(tmp_path, monkeypatch, change):
    value = bare_target(tmp_path)
    root, git_manifest = source_tree(directory(tmp_path / "code-fixture"))
    value.root = root
    value.request["source_git_manifest"] = git_manifest
    private(root / "protected", b"protected")
    # The protected file models restored state, excluded from source inventory.
    (root / "data").mkdir(mode=0o700)
    (root / "protected").rename(root / "data/protected")
    expected_db = {
        "schema_head": "0060",
        "table_counts": {"audit_events": 1},
        "audit": {"sequence": 1, "event_hash": "hash"},
        "ciphertexts": {},
        "sentinel": {"value": "ack"},
    }
    redis_expected = {"persistent": {"sha256": "hash", "expires_ms": None}}
    private(value.snapshot / "redis-inventory.json", json.dumps(redis_expected).encode())
    value.manifest = {
        "data": {
            "database": expected_db,
            "redis": {"inventory": "redis-inventory.json"},
            "protected_purposes": {"SECRET_KEY": "hash"},
        }
    }
    value.restored_files = {"data/protected": {"restored_sha256": target.sha256(root / "data/protected")}}
    value.config = {"SECRET_KEY": "synthetic"}
    monkeypatch.setitem(sys.modules, "artifacts", SimpleNamespace(validate_snapshot=lambda _p, **_kw: value.manifest))
    target.canonicalize_source(root, git_manifest)
    monkeypatch.setitem(
        sys.modules,
        "source_capture",
        SimpleNamespace(
            read_database_state=lambda *_a, **_kw: (
                expected_db | ({"table_counts": {"audit_events": 0}} if change == "database" else {})
            ),
            read_redis_inventory=lambda *_a, **_kw: {} if change == "redis" else redis_expected,
        ),
    )
    monkeypatch.setattr(
        value,
        "app_python",
        lambda *_a, **_kw: {"ready_exact": change != "maintenance", "matching_queued": 1, "redis_sentinel": True},
    )
    if change == "files":
        (root / "data/protected").write_bytes(b"tampered")
    reasons = {
        "files": "restored_private_file_drift",
        "database": "restored_database_counts",
        "redis": "redis_missing_unexpired",
        "maintenance": "captured_maintenance_not_present",
    }
    with pytest.raises(target.RecoveryError, match=reasons[change]):
        value.verify_restored_state()
    assert not (value.output / "before-startup.json").exists()


def test_runtime_ui_drift_refuses_before_any_success_receipt(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    ui = value.root / "apps/operator-ui/src/console/app.js"
    ui.parent.mkdir(parents=True)
    ui.write_bytes(b"qualified bundle")
    monkeypatch.setattr(
        value, "call", lambda args, **_kw: b"wrong bundle" if "app.js" in args[-1] else b'{"ready":true}'
    )
    monkeypatch.setitem(sys.modules, "source_capture", SimpleNamespace(read_database_state=lambda *_a, **_kw: {}))
    with pytest.raises(target.RecoveryError, match="served_ui"):
        value.runtime_proof()
    assert not (value.output / "runtime-proof.json").exists()


def test_actual_helper_verifies_volume_image_labels_and_preserves_namespace(tmp_path, monkeypatch):
    value = bare_target(tmp_path)
    calls = []
    identifier = "e" * 64

    def docker(*args, **_kwargs):
        calls.append(args)
        if args[0] == "create":
            return identifier.encode()
        return json.dumps(
            [
                {
                    "Id": identifier,
                    "Name": "/kp-offhost-postgres-restore-" + value.suffix,
                    "Config": {
                        "Image": value.model["services"]["postgres"]["image"],
                        "Labels": {"kp.offhost.run": value.run_id},
                    },
                    "HostConfig": {"NetworkMode": "none"},
                    "Mounts": [{"Name": "new-volume", "Type": "volume", "Destination": "/var/lib/postgresql/data"}],
                }
            ]
        ).encode()

    monkeypatch.setattr(value, "docker", docker)
    assert value.helper("postgres-restore", "postgres", "new-volume", extra=[], arguments=[]) == identifier
    assert calls[0][0] == "create"
    assert "--network" in calls[0] and "none" in calls[0]
    assert "--rm" not in calls[0] and "rm" not in calls[0]


@pytest.mark.parametrize("field", ["image", "volume", "run"])
def test_helper_scope_drift_refuses_before_start(tmp_path, monkeypatch, field):
    value = bare_target(tmp_path)
    calls = []
    identifier = "e" * 64
    row = {
        "Id": identifier,
        "Name": "/kp-offhost-postgres-restore-" + value.suffix,
        "Config": {"Image": value.model["services"]["postgres"]["image"], "Labels": {"kp.offhost.run": value.run_id}},
        "HostConfig": {"NetworkMode": "none"},
        "Mounts": [{"Name": "new-volume", "Type": "volume", "Destination": "/var/lib/postgresql/data"}],
    }
    if field == "image":
        row["Config"]["Image"] = "unqualified-image"
    elif field == "volume":
        row["Mounts"][0]["Name"] = "preserved-existing-volume"
    else:
        row["Config"]["Labels"]["kp.offhost.run"] = "unrelated-run"

    def docker(*args, **_kwargs):
        calls.append(args)
        return identifier.encode() if args[0] == "create" else json.dumps([row]).encode()

    monkeypatch.setattr(value, "docker", docker)
    with pytest.raises(target.RecoveryError, match="helper_"):
        value.helper("postgres-restore", "postgres", "new-volume", extra=[], arguments=[])
    assert all(args[0] != "start" for args in calls)


@pytest.mark.parametrize("change", [None, "cwd", "role", "environment", "source", "uid", "argv"])
def test_actual_native_child_binding_checks_all_thirteen_source_owned_children(tmp_path, change):
    root = directory(tmp_path / "app")
    proc = directory(tmp_path / "proc")
    (root / "data/run").mkdir(parents=True)
    for index, name in enumerate(target.APP_CHILDREN):
        pid = str(2000 + index)
        private(root / "data/run" / (name + ".pid"), pid.encode())
        directory(proc / pid)
        cwd = root if not (change == "cwd" and index == 0) else tmp_path
        (proc / pid / "cwd").symlink_to(cwd, target_is_directory=True)
        role = name.removeprefix("worker-") if name.startswith("worker-") else ""
        if change == "role" and name == "worker-mailbox":
            role = "reply-mailbox"
        tail = ["kp-worker", role] if name.startswith("worker-") else ["kp-" + name]
        args = ["uv", "run", "--frozen", "--no-sync", *tail]
        if change == "argv" and index == 0:
            args.append("--unqualified-argument")
        private(proc / pid / "cmdline", ("\0".join(args) + "\0").encode())
        environment = b"VIRTUAL_ENV=" + str(root / ".venv").encode() + b"\0"
        if index == 0 and change == "environment":
            environment = b"OTHER_ENV=not-a-venv\0"
        elif index == 0 and change == "source":
            environment = b"VIRTUAL_ENV=/unqualified/source/.venv\0"
        private(proc / pid / "environ", environment)
    if change:
        with pytest.raises(target.RecoveryError, match="native_"):
            target.validate_process_bindings(root, proc=proc, uid=os.geteuid() + int(change == "uid"))
    else:
        assert len(target.validate_process_bindings(root, proc=proc, uid=os.geteuid())) == 13


@pytest.mark.parametrize("outcome", ["consumed", "stale", "failed"])
def test_runtime_requires_consumed_maintenance_and_fresh_actual_heartbeat(tmp_path, monkeypatch, outcome):
    value = bare_target(tmp_path)
    value.app = {"schema_head": "0060"}
    value.application_started = 100
    value.prior_maintenance = {"heartbeat_epoch": 90}
    value.config = {"SECRET_KEY": "synthetic"}
    database = {
        "schema_head": "0060",
        "ciphertexts": {"recipient.mailbox": {"count": 1, "sha256": "digest"}},
        "sentinel": {"value": "ack"},
        "audit": {"sequence": 5, "event_hash": "prefix"},
    }
    value.manifest = {
        "data": {"database": database, "redis": {}, "protected_purposes": target.purpose_fingerprints(value.config)}
    }
    ui = value.root / "apps/operator-ui/src/console/app.js"
    ui.parent.mkdir(parents=True)
    ui.write_bytes(b"qualified-ui")
    monkeypatch.setattr(
        value, "call", lambda args, **_kw: b"qualified-ui" if "app.js" in args[-1] else b'{"ready":true}'
    )
    monkeypatch.setattr(
        target,
        "validate_process_bindings",
        lambda *_a, **_kw: {name: index for index, name in enumerate(target.APP_CHILDREN)},
    )
    monkeypatch.setitem(sys.modules, "source_capture", SimpleNamespace(read_database_state=lambda *_a, **_kw: database))
    observed = []

    def probe(script, **_kwargs):
        if script == target.CONFIG_PROBE:
            return value.config
        if script == target.AUDIT_PREFIX_PROBE:
            return {"verified": True}
        observed.append("maintenance")
        return {
            "matching_queued": 0,
            "matching_failed": int(outcome == "failed"),
            "heartbeat_epoch": 105 if outcome == "consumed" else 90,
        }

    def bounded_poll(operation, **_kwargs):
        result = operation()
        if not result:
            raise target.RecoveryError("target_readiness_deadline")
        return result

    monkeypatch.setattr(value, "app_python", probe)
    monkeypatch.setattr(value, "wait", bounded_poll)
    if outcome == "consumed":
        proof = value.runtime_proof()
        assert proof["maintenance"]["heartbeat_epoch"] == 105
        assert proof["readiness_endpoints"] == 2 and len(proof["native_children"]) == 13
    else:
        with pytest.raises(target.RecoveryError, match="maintenance_failed|readiness_deadline"):
            value.runtime_proof()
    assert observed == ["maintenance"]


def test_new_git_code_permissions_are_canonical_despite_private_umask(tmp_path):
    root, manifest = source_tree(tmp_path)
    initializer = root / "infrastructure/containers/postgres-init/001-roles.sh"
    initializer.parent.mkdir(mode=0o700, parents=True)
    raw = b"#!/bin/sh\nprintf synthetic-init\n"
    private(initializer, raw)
    manifest[initializer.relative_to(root).as_posix()] = {
        "mode": "100644",
        "blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest(),
    }
    # Before normalization, the initializer is unreadable by the container UID.
    assert initializer.stat().st_mode & 0o777 == 0o600
    target.canonicalize_source(root, manifest)
    assert initializer.read_bytes() == raw and initializer.stat().st_mode & 0o777 == 0o644
    assert all(
        path.stat().st_mode & 0o777 == 0o755
        for path in initializer.parents
        if path != root and path.is_relative_to(root)
    )
    assert (root / "scripts/install.sh").stat().st_mode & 0o777 == 0o755
    private(root / ".env", b"SYNTHETIC_SECRET=preserve")
    assert (root / ".env").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "change",
    ["public-port", "external-bind", "volume-driver", "privileged", "extra-named-volume", "existing-volume-alias"],
)
def test_compose_override_cannot_attach_existing_host_or_public_assets(tmp_path, monkeypatch, change):
    value = bare_target(tmp_path)
    services = {name: {} for name in target.SERVICES}
    services["postgres"] = {"image": "postgres@sha256:" + "1" * 64}
    services["redis"] = {"image": "redis@sha256:" + "2" * 64}
    model = {
        "name": target.PROJECT,
        "services": services,
        "volumes": {name: {"name": target.PROJECT + "_" + name} for name in ("postgres_data", "redis_data")},
    }
    if change == "public-port":
        services["postgres"]["ports"] = [{"host_ip": "0.0.0.0", "published": "5432"}]  # noqa: S104 - rejected fixture
    elif change == "external-bind":
        services["postgres"]["volumes"] = [{"type": "bind", "source": str(tmp_path), "target": "/unreviewed"}]
    elif change == "volume-driver":
        model["volumes"]["postgres_data"]["driver_opts"] = {
            "device": "/existing-host-state",
            "type": "none",
            "o": "bind",
        }
    elif change == "extra-named-volume":
        model["volumes"]["unreviewed"] = {
            "name": "unreviewed-host-volume",
            "driver": "local",
            "driver_opts": {"type": "none", "o": "bind", "device": "/etc"},
        }
        services["postgres"]["volumes"] = [{"type": "volume", "source": "unreviewed", "target": "/unreviewed-host"}]
    elif change == "existing-volume-alias":
        services["postgres"]["volumes"] = [{"type": "volume", "source": "redis_data", "target": "/unreviewed-host"}]
    else:
        services["postgres"]["privileged"] = True
    monkeypatch.setattr(value, "compose", lambda *_a, **_kw: json.dumps(model).encode())
    with pytest.raises(target.RecoveryError, match="compose_"):
        value.configure_compose()


@pytest.mark.parametrize("mismatch", ["hostname", "vm", "engine", "containers", "volumes"])
def test_full_restore_wrong_target_refuses_without_any_source_or_output_mutation(tmp_path, monkeypatch, mismatch):
    root, git_manifest = source_tree(tmp_path)
    root.chmod(0o755)
    home = directory(tmp_path / "home")
    app_uid = os.geteuid() or 1000
    original_stat = Path.stat

    def stat_for_app_home(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == home:
            fields = list(result)
            fields[4] = app_uid
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, "stat", stat_for_app_home)
    monkeypatch.setattr(
        target.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_name="kpqual", pw_uid=app_uid, pw_gid=os.getegid(), pw_dir=str(home)),
    )
    monkeypatch.setattr(
        target.socket, "gethostname", lambda: "wrong-host" if mismatch == "hostname" else "reviewed-host"
    )
    request = {
        "schema": target.TARGET_REQUEST_SCHEMA,
        "scope": "synthetic-qualification",
        "deadline": time.time() + 300,
        "source_root": str(root),
        "source_git_manifest": git_manifest,
        "output": str(tmp_path / "new-output"),
        "run_id": "synthetic-binding",
        "application": {"runtime_commit": target.RUNTIME_COMMIT, "bundle_commit": "a" * 40},
        "expected_engine": {"socket": target.SOCKET, "id": "reviewed-engine", "root": "/var/lib/docker"},
        "app_user": "kpqual",
        "source_deallocated": {"verified": True, "receipt_sha256": "b" * 64},
        "expected_hostname": "reviewed-host",
        "expected_vm_id": "/reviewed/vm",
    }
    before = {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file()
    }
    root_mode = root.stat().st_mode
    calls = []

    def readonly(argv, **kwargs):
        calls.append(argv)
        assert kwargs["evidence"] is None and kwargs["record"] is False
        if argv[0] == "curl":
            return b"/wrong/vm" if mismatch == "vm" else b"/reviewed/vm"
        if "info" in argv:
            return json.dumps(
                {
                    "ID": "wrong-engine" if mismatch == "engine" else "reviewed-engine",
                    "DockerRootDir": "/var/lib/docker",
                    "Architecture": "x86_64",
                    "OSType": "linux",
                }
            ).encode()
        if "ps" in argv:
            return b"existing" if mismatch == "containers" else b""
        if "volume" in argv:
            return b"existing" if mismatch == "volumes" else b""
        pytest.fail("A target mutation was attempted")

    monkeypatch.setattr(target, "command", readonly)
    with pytest.raises(target.RecoveryError, match="target_"):
        target.restore(request)
    after = {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mode)
        for path in root.rglob("*")
        if path.is_file()
    }
    assert before == after and root.stat().st_mode == root_mode
    assert not Path(request["output"]).exists()
    assert not (root / ".env").exists() and not (root / "data").exists()
    assert all(not set(argv).intersection({"create", "start", "run", "chmod", "chown"}) for argv in calls)


@pytest.mark.parametrize("extra_mount", [False, True])
def test_actual_canonical_container_rejects_extra_mounts_before_restore(tmp_path, monkeypatch, extra_mount):
    value = bare_target(tmp_path)
    identifier = "e" * 64
    name = target.PROJECT + "_postgres_data"
    mountpoint = Path(value.engine["root"]) / "volumes" / name / "_data"
    mountpoint.mkdir(parents=True)
    row = {
        "Config": {
            "Image": value.model["services"]["postgres"]["image"],
            "Labels": {"com.docker.compose.project": target.PROJECT, "com.docker.compose.service": "postgres"},
        },
        "State": {"Running": False},
        "Mounts": [
            {"Type": "volume", "Name": name, "Destination": "/var/lib/postgresql/data"},
            {
                "Type": "bind",
                "Source": str(value.root / "infrastructure/containers/postgres-init"),
                "Destination": "/docker-entrypoint-initdb.d",
                "RW": False,
            },
        ],
    }
    if extra_mount:
        row["Mounts"].append({"Type": "bind", "Source": "/etc", "Destination": "/unreviewed-host", "RW": False})
    volume = {
        "Driver": "local",
        "Options": None,
        "Mountpoint": str(mountpoint),
        "Labels": {"com.docker.compose.project": target.PROJECT, "com.docker.compose.volume": "postgres_data"},
    }
    calls = []
    monkeypatch.setattr(value, "compose", lambda *_a, **_kw: identifier.encode())

    def docker(*args, **_kwargs):
        calls.append(args)
        return json.dumps([volume if args[0] == "volume" else row]).encode()

    monkeypatch.setattr(value, "docker", docker)
    if extra_mount:
        with pytest.raises(target.RecoveryError, match="extra_mounts"):
            value.canonical_container("postgres")
        assert not any(args[0] == "volume" for args in calls)
    else:
        assert value.canonical_container("postgres") == (identifier, name)


@pytest.mark.parametrize(
    "service,profiles,accepted",
    [
        ("ai-gateway", ["ai"], True),
        ("otel-collector", ["observability"], True),
        ("ai-gateway", [], False),
        ("otel-collector", ["ai"], False),
    ],
)
def test_committed_optional_profiles_are_recognized_without_starting_them(
    tmp_path, monkeypatch, service, profiles, accepted
):
    value = bare_target(tmp_path)
    services = {name: {} for name in target.SERVICES}
    services["postgres"] = {"image": "postgres@sha256:" + "1" * 64}
    services["redis"] = {"image": "redis@sha256:" + "2" * 64}
    services[service] = {"profiles": profiles}
    model = {
        "name": target.PROJECT,
        "services": services,
        "volumes": {name: {"name": target.PROJECT + "_" + name} for name in ("postgres_data", "redis_data")},
    }
    calls = []

    def compose(*args, **_kwargs):
        calls.append(args)
        return json.dumps(model).encode()

    monkeypatch.setattr(value, "compose", compose)
    if accepted:
        value.configure_compose()
    else:
        with pytest.raises(target.RecoveryError, match="optional_profile"):
            value.configure_compose()
    assert calls == [("config", "--format", "json")]
