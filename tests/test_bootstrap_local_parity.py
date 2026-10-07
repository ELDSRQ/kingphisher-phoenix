"""Inert SQL composition and URL contracts for the development parity bootstrap."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from kp_database import grants
from psycopg import sql
from sqlalchemy.engine import URL, make_url

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_local_parity.py"


@pytest.fixture
def bootstrap(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("KP_DISABLE_DOTENV", "1")
    spec = importlib.util.spec_from_file_location("kp_local_parity_bootstrap", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RoleConnection:
    def __init__(self, *, exists: bool) -> None:
        self.exists = exists
        self.queries: list[tuple[str, dict[str, str]]] = []
        self.ddl: list[sql.Composable] = []
        # No independent transaction API: the enclosing SQLAlchemy connection
        # must retain ownership instead of committing the driver separately.
        self.connection = SimpleNamespace(driver_connection=SimpleNamespace(execute=self.ddl.append))

    def execute(self, statement: Any, parameters: dict[str, str]) -> Any:
        self.queries.append((str(statement), parameters))
        return SimpleNamespace(scalar=lambda: int(self.exists))


@pytest.mark.parametrize("exists", [False, True], ids=["create", "alter"])
@pytest.mark.parametrize(
    ("password", "literal"),
    [
        ("synthetic-ordinary", "'synthetic-ordinary'"),
        ("synthetic'quote", "'synthetic''quote'"),
        ("synthetic@at", "'synthetic@at'"),
        ("synthetic:colon", "'synthetic:colon'"),
        ("synthetic'@:value", "'synthetic''@:value'"),
        ("synthetic'; SELECT 1; --", "'synthetic''; SELECT 1; --'"),
    ],
    ids=["ordinary", "quote", "at", "colon", "combined", "sql-looking"],
)
def test_role_password_uses_driver_literal_without_changing_role_flags(
    bootstrap: ModuleType, exists: bool, password: str, literal: str
) -> None:
    connection = _RoleConnection(exists=exists)

    bootstrap._create_or_alter_role(connection, "kp_operator", password)

    assert connection.queries == [("SELECT 1 FROM pg_roles WHERE rolname = :role_name", {"role_name": "kp_operator"})]
    assert len(connection.ddl) == 1
    assert isinstance(connection.ddl[0], sql.Composed)
    expected = f'{"ALTER" if exists else "CREATE"} ROLE "kp_operator" LOGIN PASSWORD {literal}'
    if not exists:
        expected += " NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    assert connection.ddl[0].as_string() == expected


def test_role_name_is_composed_as_an_identifier(bootstrap: ModuleType) -> None:
    connection = _RoleConnection(exists=True)

    bootstrap._create_or_alter_role(connection, 'synthetic"role', "synthetic-ordinary")

    assert connection.ddl[0].as_string() == 'ALTER ROLE "synthetic""role" LOGIN PASSWORD \'synthetic-ordinary\''


def test_missing_driver_connection_fails_before_role_ddl(bootstrap: ModuleType) -> None:
    connection = _RoleConnection(exists=False)
    connection.connection.driver_connection = None

    with pytest.raises(RuntimeError, match="database driver connection is unavailable"):
        bootstrap._create_or_alter_role(connection, "kp_operator", "synthetic-ordinary")

    assert not connection.ddl


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
@pytest.mark.parametrize("password", ["synthetic-ordinary", "synthetic'@:value"])
def test_runtime_probe_replaces_credentials_and_preserves_target(
    bootstrap: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
    password: str,
) -> None:
    original = URL.create(
        "postgresql+psycopg",
        username="synthetic_nondefault_admin",
        password="synthetic-old@password:quote'",
        host=host,
        port=6543,
        database="kingphisher",
        query={"sslmode": "prefer", "application_name": "synthetic probe", "options": "-c statement_timeout=5000"},
    )
    engines: list[Any] = []

    def create_engine(database_url: str) -> Any:
        url = make_url(database_url)
        workload = grants.workload_for_role(url.username)
        state = SimpleNamespace(url=url, rolled_back=False, disposed=False, queries=0)

        def execute(statement: Any, parameters: dict[str, str]) -> Any:
            assert str(statement) == "SELECT has_table_privilege(:t, :v)"
            state.queries += 1
            allowed = grants.expected_table_privilege(
                workload, parameters["t"].removeprefix("public."), parameters["v"]
            )
            return SimpleNamespace(scalar=lambda: allowed)

        def rollback() -> None:
            state.rolled_back = True

        def dispose() -> None:
            state.disposed = True

        class ProbeContext:
            def __enter__(self) -> Any:
                return SimpleNamespace(execute=execute, rollback=rollback)

            def __exit__(self, *_args: object) -> None:
                return None

        state.connect = ProbeContext
        state.dispose = dispose
        engines.append(state)
        return state

    monkeypatch.setattr(bootstrap, "create_db_engine", create_engine)

    bootstrap._probe_runtime_privileges(original.render_as_string(hide_password=False), password)

    assert [engine.url.username for engine in engines] == list(grants.RUNTIME_ROLES.values())
    for engine in engines:
        assert engine.url.password == password
        assert engine.url.drivername == original.drivername
        assert engine.url.host == original.host
        assert engine.url.port == original.port
        assert engine.url.database == original.database
        assert engine.url.query == original.query
        assert engine.rolled_back and engine.disposed
        expected_queries = len(bootstrap.all_matrix_tables() | bootstrap.SENSITIVE_TABLES) * len(grants.TABLE_VERBS)
        assert engine.queries == expected_queries
    assert capsys.readouterr().out == "KP-008 runtime privilege probe passed\n"


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "127.0.0.1", "::1"])
def test_local_guard_accepts_only_supported_loopback_database(
    bootstrap: ModuleType, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    url = URL.create("postgresql+psycopg", host=host, database="kingphisher")
    monkeypatch.setattr(bootstrap, "create_db_engine", lambda _url: SimpleNamespace(url=url))

    bootstrap._require_local_database(url.render_as_string())


@pytest.mark.parametrize(
    ("host", "database"),
    [
        ("example.invalid", "kingphisher"),
        ("192.168.1.105", "kingphisher"),
        (None, "kingphisher"),
        ("127.0.0.1", "postgres"),
        ("localhost", "synthetic-other"),
    ],
)
def test_local_guard_rejects_remote_or_other_database_before_writes(
    bootstrap: ModuleType, monkeypatch: pytest.MonkeyPatch, host: str | None, database: str
) -> None:
    url = URL.create("postgresql+psycopg", host=host, database=database)
    monkeypatch.setattr(bootstrap, "create_db_engine", lambda _url: SimpleNamespace(url=url))

    with pytest.raises(RuntimeError, match="restricted to the loopback kingphisher development database"):
        bootstrap._require_local_database(url.render_as_string())
