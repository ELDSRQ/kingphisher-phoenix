"""Security boundaries for GUI onboarding connection tests."""

from __future__ import annotations

import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import HTTPException, Request
from kp_operator_api import console
from kp_telemetry.errors import ConflictError


def _dns_answer(ip: str, port: int) -> tuple[int, int, int, str, tuple[Any, ...]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr: tuple[Any, ...] = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def _request(env_file: Path, *, managed: bool = False) -> Request:
    settings = SimpleNamespace(
        config_is_managed=managed,
        dev_auth_mode=not managed,
        env_file=str(env_file),
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    return cast(Request, request)


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")


@pytest.mark.parametrize(
    "address",
    (
        "10.20.30.40",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fe80::1",
    ),
)
def test_http_probe_blocks_non_public_and_metadata_addresses(address: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer(address, port)],
    )
    monkeypatch.setattr(
        console,
        "_pinned_http_status",
        lambda *_args, **_kwargs: pytest.fail("a blocked address must not be contacted"),
    )

    assert console._probe_http("https://provider.example/health") == (False, "policy")


def test_http_probe_rejects_mixed_public_private_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [
            _dns_answer("93.184.216.34", port),
            _dns_answer("169.254.169.254", port),
        ],
    )
    monkeypatch.setattr(
        console,
        "_pinned_http_status",
        lambda *_args, **_kwargs: pytest.fail("mixed DNS answers must fail closed"),
    )

    assert console._probe_http("https://provider.example/health") == (False, "policy")


def test_http_probe_resolves_once_and_passes_only_the_pinned_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolutions: list[str] = []
    contacts: list[tuple[str, str]] = []

    def resolve(host: str, port: int, **_kwargs: object) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        resolutions.append(host)
        # A second lookup would model a rebind to the metadata service. The
        # probe must never perform it.
        ip = "93.184.216.34" if len(resolutions) == 1 else "169.254.169.254"
        return [_dns_answer(ip, port)]

    def status(raw: str, target: console._ResolvedTarget, _headers: dict[str, str] | None) -> int:
        contacts.append((raw, target.ip))
        return 204

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(console, "_pinned_http_status", status)

    assert console._probe_http("https://provider.example/health") == (True, None)
    assert resolutions == ["provider.example"]
    assert contacts == [("https://provider.example/health", "93.184.216.34")]


def test_http_probe_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("93.184.216.34", port)],
    )

    def status(raw: str, _target: console._ResolvedTarget, _headers: dict[str, str] | None) -> int:
        calls.append(raw)
        return 302

    monkeypatch.setattr(console, "_pinned_http_status", status)

    assert console._probe_http("https://provider.example/redirect") == (True, None)
    assert calls == ["https://provider.example/redirect"]


def test_http_probe_accepts_auth_challenge_only_for_explicit_reachability_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("93.184.216.34", port)],
    )
    monkeypatch.setattr(console, "_pinned_http_status", lambda *_args, **_kwargs: 401)

    assert console._probe_http("https://provider.example/protected", reachable_only=True) == (False, "auth")
    assert console._probe_http(
        "https://provider.example/protected",
        reachable_only=True,
        accept_auth_challenge=True,
    ) == (True, None)
    assert console._probe_http(
        "https://provider.example/protected",
        headers={"Authorization": "Bearer explicit"},
        reachable_only=True,
        accept_auth_challenge=False,
    ) == (False, "auth")


def test_http_probe_can_require_2xx_for_authenticated_read_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("93.184.216.34", port)],
    )
    monkeypatch.setattr(console, "_pinned_http_status", lambda *_args, **_kwargs: 302)

    assert console._probe_http(
        "https://graph.microsoft.com/v1.0/users/mailbox/messages/delta",
        headers={"Authorization": "Bearer explicit"},
        require_2xx=True,
    ) == (False, "http_error")


def test_http_probe_refuses_credentials_over_public_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("plaintext credentials must be rejected before DNS"),
    )

    assert console._probe_http(
        "http://provider.example/health", headers={"Authorization": "Bearer transient-secret"}
    ) == (False, "transport")


def test_pinned_https_preserves_original_hostname_for_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    wrapped: list[tuple[object, str | None]] = []
    raw_socket = SimpleNamespace(close=lambda: None)

    class Context:
        def wrap_socket(self, sock: object, *, server_hostname: str | None = None) -> object:
            wrapped.append((sock, server_hostname))
            return object()

    connection = object.__new__(console._PinnedHTTPSConnection)
    connection._pinned_target = console._ResolvedTarget(socket.AF_INET, ("93.184.216.34", 443), "93.184.216.34")
    connection._tls_context = cast(Any, Context())
    connection.host = "provider.example"
    connection.timeout = 3.0
    monkeypatch.setattr(console, "_connect_pinned", lambda *_args, **_kwargs: raw_socket)

    connection.connect()
    assert wrapped == [(raw_socket, "provider.example")]


def test_only_explicit_documented_development_loopback_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("127.0.0.1", port)],
    )
    monkeypatch.setattr(console, "_pinned_http_status", lambda *_args, **_kwargs: 204)

    assert console._probe_http("http://localhost:8282/propose", allow_loopback=True) == (True, None)
    assert console._probe_http("http://attacker.example:8282/propose", allow_loopback=True) == (
        False,
        "policy",
    )


def test_smtp_probe_blocks_private_resolution_before_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("10.0.0.25", port)],
    )
    monkeypatch.setattr(
        console,
        "_PinnedSMTP",
        lambda *_args, **_kwargs: pytest.fail("blocked SMTP must not receive credentials"),
    )

    assert console._probe_smtp("smtp.example:587", True, username="saved", password="secret") == (
        False,
        "policy",
    )


def test_smtp_probe_refuses_credentials_over_public_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("plaintext credentials must be rejected before DNS"),
    )

    assert console._probe_smtp("smtp.example:25", False, username="transient-user", password="transient-secret") == (
        False,
        "transport",
    )


def test_implicit_smtp_tls_uses_original_hostname_with_pinned_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapped: list[tuple[object, str | None]] = []
    raw_socket = SimpleNamespace(close=lambda: None)

    class Context:
        def wrap_socket(self, sock: object, *, server_hostname: str | None = None) -> object:
            wrapped.append((sock, server_hostname))
            return object()

    client = object.__new__(console._PinnedSMTPSSL)
    client._pinned_target = console._ResolvedTarget(socket.AF_INET, ("93.184.216.34", 465), "93.184.216.34")
    client._tls_hostname = "smtp.provider.example"
    client.context = cast(Any, Context())
    monkeypatch.setattr(console, "_connect_pinned", lambda *_args, **_kwargs: raw_socket)

    client._get_socket("smtp.provider.example", 465, 3.0)
    assert wrapped == [(raw_socket, "smtp.provider.example")]


@pytest.mark.parametrize(
    ("component", "saved_values", "transient_values", "expected_url"),
    (
        (
            "graph",
            {
                "KP_WORKER_GRAPH_BASE_URL": "https://graph.trusted.example",
                "KP_WORKER_GRAPH_BEARER_TOKEN": "stored-graph-token",
                "KP_WORKER_GRAPH_API_KEY": "stored-graph-key",
            },
            {"KP_WORKER_GRAPH_BASE_URL": "https://attacker.example"},
            "https://attacker.example/users",
        ),
        (
            "ai",
            {
                "KP_WORKER_AI_BASE_URL": "https://ai.trusted.example",
                "KP_WORKER_AI_BEARER_TOKEN": "stored-ai-token",
                "KP_WORKER_AI_API_KEY": "stored-ai-key",
            },
            {"KP_WORKER_AI_BASE_URL": "https://attacker.example"},
            "https://attacker.example/propose",
        ),
        (
            "mailbox",
            {
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail.trusted.example",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME": "stored-user",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "stored-password",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "stored-mail-token",
            },
            {"KP_WORKER_REPORTED_MAILBOX_URL": "https://attacker.example"},
            "https://attacker.example/api/v1/messages",
        ),
    ),
)
def test_transient_http_destination_never_receives_stored_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    component: str,
    saved_values: dict[str, str],
    transient_values: dict[str, str],
    expected_url: str,
) -> None:
    env_file = tmp_path / ".env"
    _write_env(env_file, saved_values)
    calls: list[tuple[str, dict[str, str]]] = []

    def probe(url: str, *, headers: dict[str, str] | None = None, **_kwargs: object) -> tuple[bool, None]:
        calls.append((url, headers or {}))
        return True, None

    monkeypatch.setattr(console, "_probe_http", probe)
    result = console.test_onboarding_connection(
        console.ConnectionTest(component=component, values=transient_values),
        _request(env_file),
    )

    assert result["ok"] is True
    assert calls == [(expected_url, {})]


def test_transient_smtp_destination_never_receives_stored_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    _write_env(
        env_file,
        {
            "KP_WORKER_SMTP_ADDRESS": "smtp.trusted.example:587",
            "KP_WORKER_SMTP_USERNAME": "stored-user",
            "KP_WORKER_SMTP_PASSWORD": "stored-password",
            "KP_WORKER_SMTP_STARTTLS": "true",
        },
    )
    calls: list[tuple[str, str | None, str | None]] = []

    def probe(
        address: str,
        _use_tls: bool,
        *,
        username: str | None = None,
        password: str | None = None,
        **_kwargs: object,
    ) -> tuple[bool, None]:
        calls.append((address, username, password))
        return True, None

    monkeypatch.setattr(console, "_probe_smtp", probe)
    result = console.test_onboarding_connection(
        console.ConnectionTest(component="smtp", values={"KP_WORKER_SMTP_ADDRESS": "smtp.attacker.example:587"}),
        _request(env_file),
    )

    assert result["ok"] is True
    assert calls == [("smtp.attacker.example:587", None, None)]


def test_transient_microsoft365_destination_never_receives_saved_bearer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    _write_env(
        env_file,
        {
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
            "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.microsoft.com/v1.0",
            "KP_WORKER_REPORTED_MAILBOX_ID": "reports@example.com",
            "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "inbox",
            "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "stored-mail-token",
        },
    )
    calls: list[tuple[str, dict[str, object]]] = []

    def probe(url: str, **kwargs: object) -> tuple[bool, None]:
        calls.append((url, kwargs))
        return True, None

    monkeypatch.setattr(console, "_probe_http", probe)
    result = console.test_onboarding_connection(
        console.ConnectionTest(
            component="mailbox",
            values={
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://graph.example/v1.0",
                "KP_WORKER_REPORTED_MAILBOX_ID": "reports@example.com",
                "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "inbox",
            },
        ),
        _request(env_file),
    )

    assert result["outcome"] == "reachable_unverified"
    assert calls == [
        (
            "https://graph.example/v1.0/users/reports%40example.com/mailFolders/inbox/messages/delta?$top=1&$select=id",
            {"reachable_only": True, "accept_auth_challenge": True},
        )
    ]


def test_mailbox_provider_change_never_reuses_saved_provider_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    _write_env(
        env_file,
        {
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
            "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail-gateway.example/v1.0",
            "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "stored-mailpit-token",
        },
    )
    calls: list[tuple[str, dict[str, object]]] = []

    def probe(url: str, **kwargs: object) -> tuple[bool, None]:
        calls.append((url, kwargs))
        return True, None

    monkeypatch.setattr(console, "_probe_http", probe)
    result = console.test_onboarding_connection(
        console.ConnectionTest(
            component="mailbox",
            values={
                "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail-gateway.example/v1.0",
                "KP_WORKER_REPORTED_MAILBOX_ID": "reports@example.com",
                "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": "inbox",
            },
        ),
        _request(env_file),
    )

    assert result["outcome"] == "reachable_unverified"
    assert calls[0][1] == {"reachable_only": True, "accept_auth_challenge": True}
    assert "stored-mailpit-token" not in str(calls)


def test_saved_and_complete_transient_credentials_remain_testable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    _write_env(
        env_file,
        {
            "KP_WORKER_AI_BASE_URL": "https://ai.saved.example",
            "KP_WORKER_AI_BEARER_TOKEN": "saved-token",
        },
    )
    calls: list[tuple[str, dict[str, str]]] = []

    def probe(url: str, *, headers: dict[str, str] | None = None, **_kwargs: object) -> tuple[bool, None]:
        calls.append((url, headers or {}))
        return True, None

    monkeypatch.setattr(console, "_probe_http", probe)
    saved_result = console.test_onboarding_connection(
        console.ConnectionTest(component="ai", values={}), _request(env_file)
    )
    transient_result = console.test_onboarding_connection(
        console.ConnectionTest(
            component="ai",
            values={
                "KP_WORKER_AI_BASE_URL": "https://ai.new.example",
                "KP_WORKER_AI_BEARER_TOKEN": "transient-token",
            },
        ),
        _request(env_file),
    )

    assert saved_result["ok"] is True
    assert transient_result["ok"] is True
    assert calls == [
        ("https://ai.saved.example/propose", {"Authorization": "Bearer saved-token"}),
        ("https://ai.new.example/propose", {"Authorization": "Bearer transient-token"}),
    ]


def test_managed_deployment_refuses_env_file_connection_tests(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "must-not-be-read.env"
    monkeypatch.setattr(
        console,
        "_env_values",
        lambda _path: pytest.fail("managed connection tests must not read an env file"),
    )
    monkeypatch.setattr(
        console,
        "_probe_http",
        lambda *_args, **_kwargs: pytest.fail("managed connection tests must not call provider networks"),
    )
    monkeypatch.setattr(
        console,
        "_probe_smtp",
        lambda *_args, **_kwargs: pytest.fail("managed connection tests must not call provider networks"),
    )

    with pytest.raises(ConflictError, match="local env file are disabled"):
        console.test_onboarding_connection(
            console.ConnectionTest(component="ai", values={}),
            _request(env_file, managed=True),
        )


@pytest.mark.parametrize(
    ("current", "desired"),
    (
        (
            {
                "OPERATOR_API_OIDC_MODE": "oidc",
                "OPERATOR_API_OIDC_ISSUER": "https://login.example/old",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "stored-oidc-secret",
            },
            {
                "OPERATOR_API_OIDC_ISSUER": "https://login.example/new",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "",
            },
        ),
        (
            {
                "OPERATOR_API_OIDC_MODE": "oidc",
                "OPERATOR_API_OIDC_ISSUER": "https://login.example/tenant",
                "OPERATOR_API_OIDC_CLIENT_ID": "old-client",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "stored-oidc-secret",
            },
            {
                "OPERATOR_API_OIDC_CLIENT_ID": "new-client",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "",
            },
        ),
        (
            {
                "KP_WORKER_AI_BASE_URL": "https://ai.old.example",
                "KP_WORKER_AI_BEARER_TOKEN": "stored-ai-token",
                "KP_WORKER_AI_API_KEY": "stored-ai-key",
            },
            {
                "KP_WORKER_AI_BASE_URL": "https://ai.new.example",
                "KP_WORKER_AI_BEARER_TOKEN": "",
                "KP_WORKER_AI_API_KEY": "",
            },
        ),
        (
            {
                "KP_WORKER_GRAPH_BASE_URL": "https://graph.old.example",
                "KP_WORKER_GRAPH_BEARER_TOKEN": "stored-graph-token",
                "KP_WORKER_GRAPH_API_KEY": "stored-graph-key",
            },
            {
                "KP_WORKER_GRAPH_BASE_URL": "https://graph.new.example",
                "KP_WORKER_GRAPH_BEARER_TOKEN": "",
                "KP_WORKER_GRAPH_API_KEY": "",
            },
        ),
        (
            {
                "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail.old.example",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "stored-mail-token",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "stored-mail-password",
            },
            {
                "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "",
            },
        ),
        (
            {
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail.old.example",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "stored-mail-token",
            },
            {
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail.new.example",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "",
            },
        ),
        (
            {
                "KP_WORKER_EMAIL_PROVIDER": "smtp",
                "KP_WORKER_SMTP_ADDRESS": "smtp.old.example:587",
                "KP_WORKER_SMTP_PASSWORD": "stored-smtp-password",
            },
            {
                "KP_WORKER_SMTP_ADDRESS": "smtp.new.example:587",
                "KP_WORKER_SMTP_PASSWORD": "",
            },
        ),
        (
            {
                "KP_WORKER_SMTP_ADDRESS": "smtp.old.example:587",
                "KP_WORKER_SMTP_PASSWORD": "stored-smtp-password",
            },
            {
                "KP_WORKER_SMTP_ADDRESS": "smtp.new.example:587",
                "KP_WORKER_SMTP_PASSWORD": "",
            },
        ),
        (
            {
                "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
                "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://old.communication.azure.com",
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": "stored-acs-connection",
            },
            {
                "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://new.communication.azure.com",
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": "",
            },
        ),
    ),
    ids=(
        "oidc-issuer",
        "oidc-client",
        "ai",
        "graph",
        "mailbox-provider",
        "mailbox-default",
        "smtp",
        "smtp-default",
        "acs",
    ),
)
def test_atomic_destination_rebinding_rejects_blank_preserved_credentials(
    tmp_path: Path,
    current: dict[str, str],
    desired: dict[str, str],
) -> None:
    env_file = tmp_path / ".env"
    _write_env(env_file, current)

    with pytest.raises(HTTPException, match="re-entering every configured credential") as exc_info:
        console._atomic_update_env(env_file, desired)

    assert exc_info.value.status_code == 422
    assert console._env_values(env_file) == current


@pytest.mark.parametrize(
    ("current", "desired", "expected_key"),
    (
        (
            {
                "OPERATOR_API_OIDC_MODE": "oidc",
                "OPERATOR_API_OIDC_ISSUER": "https://login.example/old",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "old-secret",
            },
            {
                "OPERATOR_API_OIDC_ISSUER": "https://login.example/new",
                "OPERATOR_API_OIDC_CLIENT_SECRET": "fresh-secret",
            },
            "OPERATOR_API_OIDC_ISSUER",
        ),
        (
            {
                "KP_WORKER_AI_BASE_URL": "https://ai.old.example",
                "KP_WORKER_AI_BEARER_TOKEN": "old-token",
                "KP_WORKER_AI_API_KEY": "old-key",
            },
            {
                "KP_WORKER_AI_BASE_URL": "https://ai.new.example",
                "KP_WORKER_AI_BEARER_TOKEN": "fresh-token",
                "KP_WORKER_AI_API_KEY": "fresh-key",
            },
            "KP_WORKER_AI_BASE_URL",
        ),
        (
            {
                "KP_WORKER_GRAPH_BASE_URL": "https://graph.old.example",
                "KP_WORKER_GRAPH_BEARER_TOKEN": "old-token",
                "KP_WORKER_GRAPH_API_KEY": "old-key",
            },
            {
                "KP_WORKER_GRAPH_BASE_URL": "https://graph.new.example",
                "KP_WORKER_GRAPH_BEARER_TOKEN": "fresh-token",
                "KP_WORKER_GRAPH_API_KEY": "fresh-key",
            },
            "KP_WORKER_GRAPH_BASE_URL",
        ),
        (
            {
                "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "mailpit",
                "KP_WORKER_REPORTED_MAILBOX_URL": "https://mail.old.example",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "old-token",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "old-password",
            },
            {
                "KP_WORKER_REPORTED_MAILBOX_PROVIDER": "microsoft365",
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "fresh-token",
                "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "fresh-password",
            },
            "KP_WORKER_REPORTED_MAILBOX_PROVIDER",
        ),
        (
            {
                "KP_WORKER_EMAIL_PROVIDER": "smtp",
                "KP_WORKER_SMTP_ADDRESS": "smtp.old.example:587",
                "KP_WORKER_SMTP_PASSWORD": "old-password",
            },
            {
                "KP_WORKER_SMTP_ADDRESS": "smtp.new.example:587",
                "KP_WORKER_SMTP_PASSWORD": "fresh-password",
            },
            "KP_WORKER_SMTP_ADDRESS",
        ),
        (
            {
                "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
                "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://old.communication.azure.com",
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": "old-connection",
            },
            {
                "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://new.communication.azure.com",
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": "fresh-connection",
            },
            "KP_WORKER_ACS_EMAIL_ENDPOINT",
        ),
    ),
    ids=("oidc", "ai", "graph", "mailbox-provider", "smtp", "acs"),
)
def test_atomic_destination_rebinding_accepts_fresh_credentials_in_same_commit(
    tmp_path: Path,
    current: dict[str, str],
    desired: dict[str, str],
    expected_key: str,
) -> None:
    env_file = tmp_path / ".env"
    _write_env(env_file, current)

    changed = console._atomic_update_env(env_file, desired)

    assert expected_key in changed
    values = console._env_values(env_file)
    assert all(values[key] == value for key, value in desired.items())


@pytest.mark.parametrize(
    "endpoint",
    (
        "http://name.communication.azure.com",
        "https://communication.azure.com",
        "https://evilcommunication.azure.com",
        "https://name.extra.communication.azure.com",
        "https://name.communication.azure.com.attacker.example",
        "https://name.communication.azure.com:444",
        "https://user@name.communication.azure.com",
        "https://name.communication.azure.com/path",
        "https://name.communication.azure.com?query=yes",
        "https://name.communication.azure.com#fragment",
        "https://-name.communication.azure.com",
        "https://name-.communication.azure.com",
        "https://name.communication.azure.com./",
    ),
)
def test_acs_endpoint_policy_rejects_nonexact_hosts_ports_and_urls(endpoint: str) -> None:
    with pytest.raises(ValueError, match="ACS endpoint"):
        console._validated_acs_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://name.communication.azure.com",
        "https://name.communication.azure.com/",
        "https://name.communication.azure.com:443",
        "https://name.communication.azure.com:443/",
    ),
)
def test_acs_endpoint_policy_accepts_only_equivalent_tls_root_urls(endpoint: str) -> None:
    assert console._validated_acs_endpoint(endpoint) == endpoint


def test_acs_connection_test_enforces_exact_endpoint_before_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    _write_env(
        env_file,
        {
            "KP_WORKER_EMAIL_PROVIDER": "azure_communication_services",
            "KP_WORKER_ACS_EMAIL_ENDPOINT": "https://name.communication.azure.com.attacker.example",
        },
    )
    monkeypatch.setattr(
        console,
        "_probe_http",
        lambda *_args, **_kwargs: pytest.fail("an invalid ACS lookalike must not be contacted"),
    )

    rejected = console.test_onboarding_connection(
        console.ConnectionTest(component="smtp", values={}),
        _request(env_file),
    )

    assert rejected["ok"] is False
    assert rejected["error_kind"] == "config"

    calls: list[str] = []

    def probe(url: str, **_kwargs: object) -> tuple[bool, None]:
        calls.append(url)
        return True, None

    monkeypatch.setattr(console, "_probe_http", probe)
    accepted = console.test_onboarding_connection(
        console.ConnectionTest(
            component="smtp",
            values={"KP_WORKER_ACS_EMAIL_ENDPOINT": "https://name.communication.azure.com"},
        ),
        _request(env_file),
    )

    assert accepted["outcome"] == "reachable_unverified"
    assert calls == ["https://name.communication.azure.com"]
