from __future__ import annotations

import asyncio
import gzip
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self, cast

import httpx
import pytest
from fastapi import Request
from kp_operator_api import console as console_module
from kp_telemetry.errors import ConflictError


class AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk


def _response(*chunks: bytes, headers: list[tuple[bytes, bytes]] | None = None) -> httpx.Response:
    return httpx.Response(200, headers=headers, stream=AsyncChunks(*chunks))


def _read(response: httpx.Response):
    return asyncio.run(console_module._bounded_setup_assist_json(response))


def _dns_answer(ip: str, port: int) -> tuple[int, int, int, str, tuple[Any, ...]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr: tuple[Any, ...] = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def _assist_request(env_file: Path, *, managed: bool = False, dev: bool = True) -> Request:
    settings = SimpleNamespace(
        config_is_managed=managed,
        dev_auth_mode=dev,
        env_file=str(env_file),
    )
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings))))


def _assist(body: console_module.SetupAssistRequest, request: Request) -> console_module.SetupAssistResponse:
    return asyncio.run(console_module.assist_onboarding(body, request))


def test_setup_assist_provider_accepts_bounded_chunked_json() -> None:
    payload = {
        "answer": "Use the approved relay.",
        "suggestions": {"KP_WORKER_SMTP_ADDRESS": "smtp.example:587"},
        "warnings": ["Run the connection test."],
    }
    encoded = json.dumps(payload).encode()
    response = _response(
        encoded[:17],
        encoded[17:],
        headers=[(b"content-length", str(len(encoded)).encode())],
    )

    assert _read(response) == payload


@pytest.mark.parametrize(
    "headers",
    [
        [(b"content-length", b"32769")],
        [(b"content-length", b"12"), (b"content-length", b"12")],
        [(b"content-length", b"twelve")],
        [(b"content-length", b"9" * 100)],
        [(b"content-length", b"-1")],
    ],
)
def test_setup_assist_provider_rejects_unsafe_declared_lengths(
    headers: list[tuple[bytes, bytes]],
) -> None:
    with pytest.raises(ValueError, match="response length|too large"):
        _read(_response(b"{}", headers=headers))


def test_setup_assist_provider_caps_decoded_chunked_bytes_without_a_length() -> None:
    response = _response(b"x" * 20_000, b"y" * 12_769)

    with pytest.raises(ValueError, match="too large"):
        _read(response)


def test_setup_assist_provider_caps_decoded_bytes_after_content_encoding() -> None:
    compressed = gzip.compress(b"x" * 32_769)
    response = _response(
        compressed,
        headers=[
            (b"content-encoding", b"gzip"),
            (b"content-length", str(len(compressed)).encode()),
        ],
    )

    with pytest.raises(ValueError, match="too large"):
        _read(response)


@pytest.mark.parametrize("body", [b"\xff", b"{not-json", b""])
def test_setup_assist_provider_rejects_malformed_utf8_or_json(body: bytes) -> None:
    with pytest.raises(ValueError, match="invalid setup assistant JSON"):
        _read(_response(body))


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"answer": "ok", "extra": "provider metadata"},
        {"answer": "ok", "suggestions": []},
        {"answer": "ok", "suggestions": {}, "warnings": ["x"] * 6},
        {"answer": "ok", "suggestions": {}, "warnings": ["x" * 501]},
        {"answer": "x" * 4001},
        {"answer": "ok", "suggestions": {f"field-{index}": "x" for index in range(33)}},
    ],
)
def test_setup_assist_provider_rejects_invalid_or_unbounded_schema(payload: object) -> None:
    with pytest.raises(ValueError, match="invalid setup assistant"):
        console_module._validated_ai_assistance(payload, frozenset())


def test_setup_assist_provider_redacts_answer_warnings_and_drops_secret_suggestions() -> None:
    secret = "provider-access-token-value"
    answer, suggestions, warnings = console_module._validated_ai_assistance(
        {
            "answer": f"The configured token={secret} should be rotated.",
            "suggestions": {"OPERATOR_API_OIDC_AUDIENCE": secret},
            "warnings": [f"Do not publish {secret}."],
        },
        frozenset({"OPERATOR_API_OIDC_AUDIENCE"}),
        secret_values=(secret,),
    )

    assert secret not in answer
    assert secret not in str(warnings)
    assert suggestions == {}
    assert "[credential removed]" in answer


def test_azure_email_assistance_excludes_stage_evidence_and_authority_fields() -> None:
    allowed = console_module._component_nonsecret_keys("azure_email")

    assert {
        "acs_sending_domain",
        "acs_sender_local_part",
        "acs_sender_display_name",
        "acs_daily_message_limit",
    } <= allowed
    assert not allowed.intersection(
        {
            "deployment_stage",
            "environment",
            "network_mode",
            "acs_resource_mode",
            "acs_existing_communication_service_id",
            "acs_existing_email_domain_id",
            "acs_dns_zone_id",
            "acs_readiness_checked_at",
        }
    )
    answer, suggestions, warnings = console_module._validated_ai_assistance(
        {
            "answer": "Use conservative pacing.",
            "suggestions": {
                "acs_daily_message_limit": "500",
                "deployment_stage": "workloads",
                "acs_dns_zone_id": "/subscriptions/authority",
            },
        },
        allowed,
    )

    assert answer == "Use conservative pacing."
    assert suggestions == {"acs_daily_message_limit": "500"}
    assert warnings == ["The AI returned a suggestion outside this setup step; it was ignored."]
    assert "protected workflow" in console_module._curated_assistance("azure_email")
    for protected_output in (
        "Select foundation_finalize",
        "The status is Verified",
        "Use this subscription ID",
        "Set the readiness checked timestamp",
        "Trust this DNS zone authority",
    ):
        assert console_module._AZURE_EMAIL_PROTECTED_AI_OUTPUT.search(protected_output)


def test_managed_setup_assist_exits_before_env_credentials_dns_or_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _assist_request(tmp_path / "must-not-be-read.env", managed=True, dev=False)
    monkeypatch.setattr(
        console_module,
        "_env_values",
        lambda *_args, **_kwargs: pytest.fail("managed setup assist must not read local configuration"),
    )
    monkeypatch.setattr(
        console_module,
        "_auth_headers",
        lambda *_args, **_kwargs: pytest.fail("managed setup assist must not load credentials"),
    )
    monkeypatch.setattr(
        console_module,
        "_resolve_setup_assist_endpoint",
        lambda *_args, **_kwargs: pytest.fail("managed setup assist must not resolve or contact a provider"),
    )
    monkeypatch.setattr(
        console_module.httpx,
        "AsyncClient",
        lambda *_args, **_kwargs: pytest.fail("managed setup assist must not create an HTTP client"),
    )

    with pytest.raises(ConflictError, match="Terraform and Key Vault"):
        _assist(
            console_module.SetupAssistRequest(component="ai", question="How do I configure this?"),
            request,
        )


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
def test_setup_assist_rejects_each_non_public_dns_answer_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "KP_WORKER_AI_BASE_URL=https://ai.provider.example\nKP_WORKER_AI_BEARER_TOKEN=stored-token\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer(address, port)],
    )
    monkeypatch.setattr(
        console_module,
        "_auth_headers",
        lambda *_args, **_kwargs: pytest.fail("credentials must not be prepared before endpoint validation"),
    )
    monkeypatch.setattr(
        console_module.httpx,
        "AsyncClient",
        lambda *_args, **_kwargs: pytest.fail("blocked setup-assist endpoint must not receive a request"),
    )

    result = _assist(
        console_module.SetupAssistRequest(component="ai", question="Help with the AI service."),
        _assist_request(env_file),
    )

    assert result.source == "curated"


def test_setup_assist_rejects_mixed_dns_and_pins_one_public_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(dev_auth_mode=False)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [
            _dns_answer("93.184.216.34", port),
            _dns_answer("169.254.169.254", port),
        ],
    )
    with pytest.raises(console_module._EndpointPolicyError, match="public"):
        console_module._resolve_setup_assist_endpoint(
            "https://ai.provider.example/gateway",
            settings=settings,
            destination_key="KP_WORKER_AI_BASE_URL",
        )

    resolutions: list[str] = []

    def public_dns(host: str, port: int, **_kwargs: object) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        resolutions.append(host)
        return [_dns_answer("93.184.216.34", port)]

    monkeypatch.setattr(socket, "getaddrinfo", public_dns)
    endpoint = console_module._resolve_setup_assist_endpoint(
        "https://ai.provider.example/gateway",
        settings=settings,
        destination_key="KP_WORKER_AI_BASE_URL",
    )

    assert resolutions == ["ai.provider.example"]
    assert endpoint.request_url == "https://93.184.216.34/gateway/setup-assist"
    assert endpoint.host_header == "ai.provider.example"
    assert endpoint.extensions == {"sni_hostname": "ai.provider.example"}


def test_setup_assist_bounds_dns_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer(f"93.184.216.{index}", port) for index in range(1, 34)],
    )

    with pytest.raises(console_module._EndpointPolicyError, match="number of addresses"):
        console_module._resolve_setup_assist_endpoint(
            "https://ai.provider.example",
            settings=SimpleNamespace(dev_auth_mode=False),
            destination_key="KP_WORKER_AI_BASE_URL",
        )


@pytest.mark.parametrize(
    ("base_url", "destination_key", "dev"),
    (
        ("http://ai.provider.example", "KP_WORKER_AI_BASE_URL", False),
        ("http://localhost:8282", "KP_WORKER_AI_BASE_URL", True),
        ("http://localhost:8283", "MOCK_AI_URL", True),
        ("http://attacker.example:8282", "MOCK_AI_URL", True),
    ),
)
def test_setup_assist_plaintext_is_limited_to_the_documented_dev_loopback(
    monkeypatch: pytest.MonkeyPatch,
    base_url: str,
    destination_key: str,
    dev: bool,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("invalid plaintext destinations must fail before DNS"),
    )

    with pytest.raises(console_module._EndpointPolicyError):
        console_module._resolve_setup_assist_endpoint(
            base_url,
            settings=SimpleNamespace(dev_auth_mode=dev),
            destination_key=destination_key,
        )


def test_setup_assist_allows_only_the_documented_dev_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("127.0.0.1", port)],
    )

    endpoint = console_module._resolve_setup_assist_endpoint(
        "http://localhost:8282",
        settings=SimpleNamespace(dev_auth_mode=True),
        destination_key="MOCK_AI_URL",
    )

    assert endpoint.request_url == "http://127.0.0.1:8282/setup-assist"
    assert endpoint.host_header == "localhost:8282"
    assert endpoint.extensions == {}


def test_setup_assist_refuses_redirect_and_disables_proxy_and_http2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "KP_WORKER_AI_BASE_URL=https://ai.provider.example\nKP_WORKER_AI_API_KEY=stored-key\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda _host, port, **_kwargs: [_dns_answer("93.184.216.34", port)],
    )

    class RedirectResponse:
        is_redirect = True
        headers = httpx.Headers({"location": "http://169.254.169.254/latest"})

        def raise_for_status(self) -> None:
            pytest.fail("redirects must be rejected explicitly")

    class Stream:
        async def __aenter__(self) -> RedirectResponse:
            return RedirectResponse()

        async def __aexit__(self, *_args: object) -> None:
            return None

    class Client:
        def __init__(self, **kwargs: object) -> None:
            captured["client"] = kwargs

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, method: str, url: str, **kwargs: object) -> Stream:
            captured["request"] = (method, url, kwargs)
            return Stream()

    monkeypatch.setattr(console_module.httpx, "AsyncClient", Client)

    result = _assist(
        console_module.SetupAssistRequest(component="ai", question="Help with the AI service."),
        _assist_request(env_file, dev=False),
    )

    assert result.source == "curated"
    assert captured["client"] == {
        "timeout": 5.0,
        "follow_redirects": False,
        "trust_env": False,
        "http2": False,
    }
    method, url, kwargs = cast(tuple[str, str, dict[str, object]], captured["request"])
    assert method == "POST"
    assert url == "https://93.184.216.34/setup-assist"
    assert kwargs["headers"] == {"Host": "ai.provider.example", "X-API-Key": "stored-key"}
    assert kwargs["extensions"] == {"sni_hostname": "ai.provider.example"}
