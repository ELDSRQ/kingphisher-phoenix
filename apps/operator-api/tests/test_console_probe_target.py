"""The local dependency probe must follow configured URLs, not a fixed port.

Regression: the probe hardcoded 127.0.0.1:5432 and :6379, so an operator whose
PostgreSQL listened on any other port saw the console report postgres down while
the application was connected to it and healthy.
"""

from kp_operator_api.console import _probe_target


def test_probe_follows_the_configured_postgres_port() -> None:
    target = _probe_target("postgresql+psycopg://kingphisher:secret@127.0.0.1:5433/kingphisher", 5432)
    assert target == ("127.0.0.1", 5433)


def test_probe_follows_the_configured_redis_host_and_port() -> None:
    assert _probe_target("redis://:secret@10.0.0.9:6380/0", 6379) == ("10.0.0.9", 6380)


def test_probe_falls_back_to_the_default_port_when_the_url_omits_one() -> None:
    assert _probe_target("postgresql+psycopg://user:pw@db.internal/kingphisher", 5432) == (
        "db.internal",
        5432,
    )


def test_probe_never_reports_credentials_as_the_host() -> None:
    host, port = _probe_target("redis://:sup3rsecret@127.0.0.1:6379/0", 6379)
    assert host == "127.0.0.1"
    assert port == 6379
    assert "sup3rsecret" not in host


def test_probe_falls_back_safely_on_a_malformed_url() -> None:
    assert _probe_target("not-a-url://[oops", 5432) == ("127.0.0.1", 5432)
