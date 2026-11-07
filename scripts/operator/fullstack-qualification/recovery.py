"""Full task-state capture and restore into fresh labeled resources only."""

from __future__ import annotations

import io
import json
import os
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any

import redis
from campaign import Campaigns
from evidence import QualificationFailure, digest, loopback_url
from sqlalchemy import MetaData, Table, create_engine, func, inspect, select, text
from sqlalchemy.engine import Engine
from stack import Stack


def exclusive_bytes(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)


def copy_out(stack: Stack, identifier: str) -> bytes:
    stack.owned(identifier)
    return stack.docker("cp", f"{identifier}:/data/.", "-", maximum=60)


def copy_in(stack: Stack, identifier: str, content: bytes) -> None:
    stack.owned(identifier)
    record = json.loads(stack.docker("inspect", identifier))[0]
    if record["State"]["Running"]:
        raise QualificationFailure("restore copy requires a stopped, newly created target")
    stack.docker("cp", "-", f"{identifier}:/data", input=content, maximum=60)


def table_counts(engine: Engine) -> dict[str, int]:
    """Exact counts from only the task-owned single application database."""
    with engine.connect() as connection:
        names = inspect(connection).get_table_names(schema="public")
        return {
            name: int(
                connection.scalar(select(func.count()).select_from(Table(name, MetaData(), schema="public"))) or 0
            )
            for name in names
        }


def restart_restored_service(stack: Stack, services: dict[str, Any], kind: str, snapshot: bytes) -> None:
    """Restore only the fresh target, then rediscover Docker's dynamic ports."""
    service = services[kind]
    stack.owned_restored_service(service, kind)
    identifier = service["id"]
    stack.mutate("stop", identifier, "--time", "15")
    copy_in(stack, identifier, snapshot)
    stack.mutate("start", identifier)
    stack.refresh_service_bindings(service, kind)


def verify_restored_redis(stack: Stack, services: dict[str, Any], marker: str) -> None:
    url = loopback_url(f"redis://127.0.0.1:{services['redis']['ports'][6379]}/0", {"redis"})
    restored_cache = redis.Redis.from_url(url, socket_timeout=3, socket_connect_timeout=3)
    deadline = time.monotonic() + stack.evidence.remaining(60)
    try:
        while time.monotonic() < deadline:
            try:
                if restored_cache.get("kp:qualification:acknowledged-sentinel") != marker.encode():
                    raise QualificationFailure("acknowledged Redis sentinel missing")
                return
            except redis.RedisError:
                time.sleep(0.25)
        raise QualificationFailure("restored Redis readiness deadline exceeded")
    finally:
        restored_cache.close()


def qualify_recovery(stack: Stack, source_services: dict[str, Any], campaigns: Campaigns) -> Campaigns:
    evidence = stack.evidence
    # Stop only the owned delivery process, then obtain an HTTP-acknowledged
    # reviewed-direct send while its real Redis/outbox work remains pending.
    stack.quiesce(only={"source-worker-delivery"})
    pending = campaigns.launch(5, "restore-pending")
    pending_states = campaigns.observe(pending)
    if sum(pending_states.values()) != 5 or any(state.lower() != "queued" for state in pending_states):
        raise QualificationFailure("recovery workload did not remain queued before checkpoint")
    evidence.json("private-campaign-snapshot.json", campaigns.campaigns)
    marker = str(uuid.uuid4())
    with campaigns.engine.begin() as connection:
        connection.execute(
            text("CREATE TABLE qualification_recovery_sentinel (id text PRIMARY KEY, acknowledged_at timestamptz)")
        )
        connection.execute(text("INSERT INTO qualification_recovery_sentinel VALUES (:id,now())"), {"id": marker})
    cache = redis.Redis.from_url(campaigns.endpoints["redis"], socket_timeout=3, socket_connect_timeout=3)
    cache.set("kp:qualification:acknowledged-sentinel", marker)
    if cache.get("kp:qualification:acknowledged-sentinel") != marker.encode():
        raise QualificationFailure("Redis sentinel was not acknowledged")
    cutoff = time.time()
    # Application processes are quiesced before either data store is captured.
    # Capture every synthetic configuration/key identity with the same boundary.
    stack.quiesce()
    source_counts = table_counts(campaigns.engine)
    campaigns.engine.dispose()
    campaigns.client.close()
    source_pg = source_services["postgres"]["id"]
    stack.owned(source_pg)
    snapshots = {
        "postgres.dump": stack.docker("exec", source_pg, "pg_dump", "-U", "postgres", "-d", "qualification", "-Fc"),
        "globals.sql": stack.docker("exec", source_pg, "pg_dumpall", "-U", "postgres", "--globals-only"),
    }
    anchor_root = evidence.root / "source-anchor-evidence"
    anchor_archive = io.BytesIO()
    with tarfile.open(fileobj=anchor_archive, mode="w") as archive:
        for path in sorted(anchor_root.rglob("*")):
            if path.is_symlink():
                raise QualificationFailure("anchor snapshot refuses symbolic links")
            if path.is_file():
                if path.stat().st_size > 1024 * 1024:
                    raise QualificationFailure("anchor snapshot file exceeded bound")
                archive.add(path, arcname=str(path.relative_to(anchor_root)), recursive=False)
    snapshots["anchor-data.tar"] = anchor_archive.getvalue()
    # These containers belong exclusively to this qualification. Stopping them
    # closes SQLite/AOF files before copying; their identities/volumes persist.
    for kind in ("redis", "mailpit"):
        identifier = source_services[kind]["id"]
        stack.mutate("stop", identifier, "--time", "15")
        snapshots[f"{kind}-data.tar"] = copy_out(stack, identifier)
    cache.close()
    for name, content in snapshots.items():
        exclusive_bytes(evidence.root / name, content)
    private_files = [
        *sorted(evidence.root.glob("*private*.json")),
        evidence.root / "fixture-scope.json",
        evidence.root / "profile.json",
    ]
    evidence.json(
        "checkpoint-manifest.json",
        {
            "cutoff_unix": cutoff,
            "capture_completed_unix": time.time(),
            "sentinel": marker,
            "mode": "quiesced-consistent-full-state",
            "table_counts": source_counts,
            "scope": "synthetic-task-only",
            "files": {
                path.name: {"sha256": digest(path), "bytes": path.stat().st_size}
                for path in [*(evidence.root / name for name in snapshots), *private_files]
            },
            "key_identities": {
                key: __import__("hashlib").sha256(value.encode()).hexdigest() for key, value in stack.secrets.items()
            },
        },
    )
    restore_started = time.monotonic()
    manifest = json.loads((evidence.root / "checkpoint-manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if digest(evidence.root / name) != expected["sha256"]:
            raise QualificationFailure("checkpoint manifest mismatch before restore")
    recovered_configuration = evidence.root / "restored-private-config"
    recovered_configuration.mkdir(mode=0o700, exist_ok=False)
    for name in [path.name for path in private_files]:
        target_config = recovered_configuration / name
        exclusive_bytes(target_config, (evidence.root / name).read_bytes())
        if digest(target_config) != manifest["files"][name]["sha256"]:
            raise QualificationFailure("recovered private configuration hash mismatch")
    source_configuration = stack.load_recovered_configuration(recovered_configuration)
    fixture_scope = json.loads((recovered_configuration / "fixture-scope.json").read_text())
    campaign_scope = json.loads((recovered_configuration / "private-campaign-snapshot.json").read_text())
    pending = next(row for row in campaign_scope if row["label"] == "restore-pending")
    target = stack.create_services("restored")
    target_pg = target["postgres"]["id"]
    deadline = time.monotonic() + evidence.remaining(120)
    while time.monotonic() < deadline:
        stack.owned(target_pg)
        try:
            stack.docker("exec", target_pg, "pg_isready", "-U", "postgres", maximum=5)
            break
        except QualificationFailure:
            time.sleep(0.5)
    else:
        raise QualificationFailure("restore PostgreSQL readiness deadline")
    # The clean postgres image already owns its bootstrap superuser. Omit only
    # that exact duplicate CREATE; preserve all other role/ownership statements
    # and fail on any unexpected restore error.
    globals_sql = snapshots["globals.sql"].decode()
    if globals_sql.count("CREATE ROLE postgres;") != 1:
        raise QualificationFailure("unexpected fresh-cluster globals format")
    globals_sql = globals_sql.replace("CREATE ROLE postgres;", "-- existing fresh bootstrap postgres role", 1)
    stack.owned(target_pg)
    stack.docker(
        "exec",
        "-i",
        target_pg,
        "psql",
        "-U",
        "postgres",
        "-d",
        "qualification",
        "--set",
        "ON_ERROR_STOP=1",
        input=globals_sql.encode(),
    )
    stack.docker(
        "exec",
        "-i",
        target_pg,
        "pg_restore",
        "-U",
        "postgres",
        "-d",
        "qualification",
        "--exit-on-error",
        input=snapshots["postgres.dump"],
        maximum=180,
    )
    for kind in ("redis", "mailpit"):
        restart_restored_service(stack, target, kind, snapshots[f"{kind}-data.tar"])
    restored_url = stack.connection_urls(target)
    engine = create_engine(restored_url, connect_args={"connect_timeout": 3})
    if table_counts(engine) != manifest["table_counts"]:
        raise QualificationFailure("restored application table counts do not match the quiesced checkpoint")
    with engine.connect() as connection:
        if connection.scalar(text("SELECT id FROM qualification_recovery_sentinel")) != marker:
            raise QualificationFailure("acknowledged PostgreSQL sentinel missing")
    engine.dispose()
    verify_restored_redis(stack, target, marker)
    anchor_target = evidence.root / "restored-anchor-evidence"
    anchor_target.mkdir(mode=0o700, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(snapshots["anchor-data.tar"]), mode="r") as archive:
        for member in archive:
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts or not member.isfile():
                raise QualificationFailure("invalid anchor snapshot member")
            target_path = anchor_target / relative
            target_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            member_source = archive.extractfile(member)
            if member_source is None:
                raise QualificationFailure("anchor snapshot member unavailable")
            exclusive_bytes(target_path, member_source.read())
    endpoints = stack.start_applications(target, "restored")
    target_configuration = json.loads((evidence.root / "restored-private-application-environment.json").read_text())
    for key, value in source_configuration.items():
        if (
            "DATABASE_URL" in key
            or "REDIS_URL" in key
            or key
            in {
                "KP_WORKER_MAILPIT_API_URL",
                "KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR",
            }
        ):
            continue
        if target_configuration.get(key) != value:
            raise QualificationFailure("recovered application configuration drifted outside endpoint rebinding")
    restored = Campaigns(stack, target, endpoints)
    restored.principals = fixture_scope["principals"]
    restored.fixture_ids = {key: fixture_scope[key] for key in ("pattern", "template", "resource", "roe")}
    restored.campaigns = campaign_scope
    restored.ready("restored")
    restored.exercise_training(campaign_scope[0], allow_completed=True)
    restored.drain(pending)
    from kp_database.audit_store import AuditStore

    audit = create_engine(restored_url.set(username="audit_writer", password=stack.secrets["audit"]))
    intent = create_engine(stack.urls["operator"])
    if AuditStore(audit, intent_engine=intent).verify():
        raise QualificationFailure("restored audit verification failed")
    audit.dispose()
    intent.dispose()
    restored.critical_probe("restored")
    campaign = restored.launch(1, "after-restore")
    restored.drain(campaign)
    restored.exercise_training(campaign)
    restored.finish_queues()
    restored.sink_counts()
    elapsed = time.monotonic() - restore_started
    if elapsed > evidence.profile.rto_seconds:
        raise QualificationFailure("isolated recovery time target exceeded")
    evidence.json(
        "recovery-result.json",
        {
            "rpo_missing_acknowledged_sentinels": 0,
            "rto_seconds": elapsed,
            "mode": "quiesced-consistent-synthetic",
            "restored_resources": target,
            "audit_verified": True,
            "configuration_rehydrated_from_verified_checkpoint": True,
            "same_host_recovery": True,
            "offhost_secret_escrow_proven": False,
            "post_restore_campaign": campaign["id"],
        },
    )
    return restored
