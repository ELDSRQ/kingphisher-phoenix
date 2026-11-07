"""Stable local operation locks and refreshed singleton/keyed-row locks.

File locks serialize processes sharing a local deployment directory; they do
not pretend to coordinate files on unrelated hosts. PostgreSQL upsert + row
locks protect counter initialization/increments across database clients too.
Lock files are private persistent inodes, never replaced or unlinked.
"""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

_GUARD = threading.Lock()
_LOCKS: dict[Path, threading.RLock] = {}
_LOCAL = threading.local()
_DESCRIPTORS: set[int] = set()


def _after_fork() -> None:
    global _GUARD, _LOCKS, _LOCAL, _DESCRIPTORS
    for descriptor in _DESCRIPTORS:
        os.close(descriptor)
    _GUARD = threading.Lock()
    _LOCKS = {}
    _LOCAL = threading.local()
    _DESCRIPTORS = set()


def _before_fork() -> None:
    _GUARD.acquire()


def _after_fork_parent() -> None:
    _GUARD.release()


os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_parent, after_in_child=_after_fork)


def lock_path(settings: Any, purpose: str) -> Path:
    # Outside data/run: wiping/rebuilding runtime markers cannot replace the
    # operation lock inode while a credential/provider mutation is in flight.
    parent = Path(getattr(settings, "env_file", "") or ".env").resolve().parent
    return parent / (".kp-console-" + purpose + ".lock")


@contextmanager
def private_file_lock(path: Path) -> Iterator[None]:
    path = path.parent.resolve() / path.name
    with _GUARD:
        guard = _LOCKS.setdefault(path, threading.RLock())
    with guard:
        held = getattr(_LOCAL, "held", None)
        if held is None:
            held = _LOCAL.held = set()
        if path in held:
            yield
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with _GUARD:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            # Include descriptors waiting for flock. The fork guard also closes
            # the open-to-registration gap before a child can inherit them.
            _DESCRIPTORS.add(descriptor)
        locked = False
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise PermissionError("private operation lock has invalid ownership or type")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True
            held.add(path)
            yield
        finally:
            held.discard(path)
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with _GUARD:
                _DESCRIPTORS.discard(descriptor)
                os.close(descriptor)


def locked_row[T](session: Session, model: type[T], identifier: Any, initial: dict[str, Any]) -> T:
    """Initialize without a missing-row race, then refresh under FOR UPDATE."""
    if isinstance(session, Session):
        dialect = session.get_bind().dialect.name
        if dialect not in {"postgresql", "sqlite"}:
            raise RuntimeError("locked counter initialization requires PostgreSQL")
        mapper = inspect(model)
        if mapper is None:
            raise RuntimeError("counter model has no database mapping")
        table = mapper.local_table
        cached = session.identity_map.get(session.identity_key(model, identifier))
        if cached is not None and session.is_modified(cached, include_collections=False):
            # A previous bump in this transaction already owns the row lock.
            # Persist its legitimate pending increment before refreshing it.
            session.flush([cached])
        with session.no_autoflush:
            if dialect == "postgresql":
                session.execute(pg_insert(table).values(**initial).on_conflict_do_nothing())
            else:
                session.execute(sqlite_insert(table).values(**initial).on_conflict_do_nothing())
            row = session.get(model, identifier, with_for_update=True, populate_existing=True)
        if row is None:
            raise RuntimeError("counter initialization did not produce a row")
        return row
    # Small dependency-injected test sessions model a single transaction. The
    # real PostgreSQL/SQLite path above always uses the conflict-safe statement.
    row = session.get(model, identifier, with_for_update=True, populate_existing=True)
    if row is None:
        row = model(**initial)
        session.add(row)
    return row
