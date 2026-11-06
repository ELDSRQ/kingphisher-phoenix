"""Read-only bounds and queue metadata, always checked before service stop."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, cast

import redis
from kp_contracts.queue import DEFAULT_QUEUE_TOPICS, JobQueue
from kp_database.base import Base
from kp_database.models import CipherText
from sqlalchemy import Table, create_engine, func, inspect, select, text

from kp_dev_upgrade.core import NORMAL, RUNS, UNIT, Blocked, require_clean_connection_environment

MAX_REDIS_KEYS = 500000
MAX_REDIS_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000
MAX_ENCRYPTED_ROWS = 10000


def queue_snapshot(url: str) -> dict[str, Any]:
    queue = JobQueue(url + "?socket_timeout=5&socket_connect_timeout=3")
    try:
        # No claim, recovery, replay, acknowledgement or queue mutation occurs.
        return {topic: queue.queue_stats(topic) for topic in DEFAULT_QUEUE_TOPICS}
    finally:
        queue.close()


def require_send_queues_drained(snapshot: dict[str, Any]) -> None:
    if set(snapshot) != set(DEFAULT_QUEUE_TOPICS):
        raise Blocked("queue_snapshot_missing_canonical_topics")
    for topic in ("deliver", "reply-mailbox", "alert"):
        if any(snapshot[topic][kind] != 0 for kind in ("ready", "processing", "delayed")):
            raise Blocked("send_or_reply_or_alert_queue_not_drained")


def bounds_preflight(cfg: dict[str, str]) -> dict[str, Any]:
    require_clean_connection_environment()
    files = 0
    project_bytes = 0
    for entry in (NORMAL / ".env", NORMAL / "docker-compose.override.yml", NORMAL / "data", UNIT):
        if not entry.exists():
            if entry.name == "docker-compose.override.yml":
                continue
            raise Blocked("required_project_state_is_missing")
        for directory, dirs, names in os.walk(entry) if entry.is_dir() else [(str(entry.parent), [], [entry.name])]:
            for name in [*dirs, *names]:
                path = Path(directory) / name
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise Blocked("project_archive_contains_link_or_special_file")
                if stat.S_ISREG(mode):
                    files += 1
                    project_bytes += path.stat().st_size
            if files > MAX_ARCHIVE_FILES:
                raise Blocked("project_archive_file_bound_exceeded")
    cache = redis.Redis.from_url(cfg["REDIS_URL"], socket_timeout=5, socket_connect_timeout=3)
    try:
        keys = int(cache.dbsize())
        memory = int(cache.info("memory")["used_memory"])
        if cache.module_list():
            raise Blocked("redis_module_types_are_unsupported_before_service_stop")
    finally:
        cache.close()
    if keys > MAX_REDIS_KEYS or memory > MAX_REDIS_BYTES:
        raise Blocked("redis_preflight_bound_exceeded_before_service_stop")
    engine = create_engine(
        cfg["DATABASE_URL"],
        connect_args={
            "connect_timeout": 3,
            "options": "-c default_transaction_read_only=on -c statement_timeout=15000",
        },
    )
    try:
        with engine.connect() as connection:
            tables = set(inspect(connection).get_table_names(schema="public"))
            encrypted = {
                cast(Table, mapper.local_table).name: int(
                    connection.scalar(select(func.count()).select_from(mapper.local_table)) or 0
                )
                for mapper in Base.registry.mappers
                if cast(Table, mapper.local_table).name in tables
                and any(isinstance(column.type, CipherText) for column in mapper.columns)
            }
            database_bytes = int(connection.scalar(text("SELECT pg_database_size(current_database())")) or 0)
    finally:
        engine.dispose()
    if max(encrypted.values(), default=0) > MAX_ENCRYPTED_ROWS:
        raise Blocked("encrypted_entity_preflight_bound_exceeded_before_service_stop")
    required = 8 * 1024**3 + 2 * project_bytes + 3 * database_bytes + 4 * memory
    free = os.statvfs(RUNS).f_bavail * os.statvfs(RUNS).f_frsize
    if free < required:
        raise Blocked("insufficient_computed_checkpoint_headroom_preserve_assets_and_stop")
    return {
        "passed": True,
        "archive_regular_files": files,
        "archive_bytes": project_bytes,
        "redis_keys": keys,
        "redis_used_memory": memory,
        "encrypted_entity_counts": encrypted,
        "database_bytes": database_bytes,
        "required_free_bytes": required,
        "observed_free_bytes": free,
        "bounds": {
            "redis_keys": MAX_REDIS_KEYS,
            "redis_bytes": MAX_REDIS_BYTES,
            "archive_files": MAX_ARCHIVE_FILES,
            "encrypted_entity_rows": MAX_ENCRYPTED_ROWS,
        },
    }
