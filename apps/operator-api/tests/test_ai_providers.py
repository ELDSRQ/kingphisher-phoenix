"""BYO-model provider store: registry + save/select routes (hermetic).

Calls the console route functions directly with a fake session, fake request,
and a temp .env (mirrors test_template_logo). No DB: the ORM ``CipherText``
column only encrypts at the DB boundary, so a fake-session row carries the
plaintext key — which is exactly what the gateway state file needs.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from kp_authorization import Principal, Role
from kp_database.models import AiGenerationProvider
from kp_operator_api import ai_providers as registry
from kp_operator_api.console.ai_providers import (
    ProviderSaveRequest,
    ProviderSelectRequest,
    list_ai_providers,
    save_ai_provider,
    select_ai_provider,
)
from kp_telemetry.errors import NotFoundError, ValidationError_


class _Scalars:
    def __init__(self, rows: list[AiGenerationProvider]) -> None:
        self._rows = rows

    def all(self) -> list[AiGenerationProvider]:
        return self._rows


class _Session:
    def __init__(self) -> None:
        self.store: dict[str, AiGenerationProvider] = {}
        self.commits = 0

    def get(self, _model: object, identifier: str) -> AiGenerationProvider | None:
        return self.store.get(identifier)

    def add(self, row: AiGenerationProvider) -> None:
        self.store[row.provider] = row

    def scalars(self, _stmt: object) -> _Scalars:
        return _Scalars(list(self.store.values()))

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commits += 1


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(self, **event: Any) -> None:
        self.events.append(event)


def _request(env_file: Path) -> Any:
    settings = SimpleNamespace(env_file=str(env_file), config_is_managed=False)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))


def _settings(env_file: Path) -> Any:
    return SimpleNamespace(env_file=str(env_file))


def _principal() -> Principal:
    return Principal(str(uuid.uuid4()), {Role.SECURITY_APPROVER})


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / ".env"
    p.write_text("KP_WORKER_AI_MODEL_ID=qwen-local\n")
    return p


# --- registry ---------------------------------------------------------------


def test_registry_has_all_expected_providers() -> None:
    assert set(registry.PROVIDERS) == {"local", "openai", "gemini", "anthropic", "openrouter", "opencode", "custom"}
    assert registry.preset("openai").needs_key is True
    assert registry.preset("local").needs_key is False
    assert registry.resolve_base_url("openai", None) == "https://api.openai.com/v1"
    assert registry.resolve_base_url("openai", "https://proxy.example/v1/") == "https://proxy.example/v1"
    assert registry.resolve_model("openai", None) == "gpt-4o"
    assert registry.resolve_model("openai", "gpt-4.1") == "gpt-4.1"


# --- list / save -------------------------------------------------------------


def test_list_defaults_to_local_active_and_hides_keys(env_file: Path) -> None:
    session = _Session()
    out = list_ai_providers(request=_request(env_file), session=session, _principal=_principal())  # type: ignore[arg-type]
    assert out["active"] == "local"
    assert out["managed"] is False
    assert {p["key"] for p in out["providers"]} == set(registry.PROVIDERS)
    assert all("api_key" not in p for p in out["providers"])  # never leak keys


def test_save_stores_key_and_model_without_echoing(env_file: Path) -> None:
    session = _Session()
    audit = _Audit()
    res = save_ai_provider(
        "openai",
        ProviderSaveRequest(api_key="sk-secret", model_id="gpt-4o"),
        request=_request(env_file),  # type: ignore[arg-type]
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert res == {"provider": "openai", "saved": True}
    assert session.store["openai"].api_key == "sk-secret"
    assert audit.events[0]["detail"]["key_set"] is True
    # a later save with a blank api_key keeps the stored one
    save_ai_provider(
        "openai",
        ProviderSaveRequest(api_key="", model_id="gpt-4.1"),
        request=_request(env_file),  # type: ignore[arg-type]
        session=session,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        principal=_principal(),
    )
    assert session.store["openai"].api_key == "sk-secret"
    assert session.store["openai"].model_id == "gpt-4.1"


def test_save_rejects_unknown_provider(env_file: Path) -> None:
    with pytest.raises(NotFoundError):
        save_ai_provider(
            "bogus",
            ProviderSaveRequest(api_key="x"),
            request=_request(env_file),  # type: ignore[arg-type]
            session=_Session(),  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            principal=_principal(),
        )


# --- select ------------------------------------------------------------------


def _select(session: _Session, env_file: Path, provider: str) -> dict[str, Any]:
    return select_ai_provider(
        ProviderSelectRequest(provider=provider),
        request=_request(env_file),  # type: ignore[arg-type]
        session=session,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        settings=_settings(env_file),
        principal=_principal(),
    )


def test_select_requires_a_saved_key(env_file: Path) -> None:
    with pytest.raises(ValidationError_):
        _select(_Session(), env_file, "openai")


def test_select_provider_writes_state_file_and_repins(env_file: Path) -> None:
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))
    out = _select(session, env_file, "openai")
    assert out["active"] is True and out["model_id"] == "gpt-4o"
    # state file written for the gateway
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state == {
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model_id": "gpt-4o",
        "api_key": "sk-secret",
        "auth_style": "bearer",
    }
    # worker model pin repinned, local pin snapshotted for restore, restart signalled
    env_text = env_file.read_text()
    assert "KP_WORKER_AI_MODEL_ID" in env_text and "gpt-4o" in env_text
    assert session.store["local"].model_id == "qwen-local"
    assert session.store["openai"].is_active is True
    assert (env_file.parent / "data" / "run" / "restart").exists()


def test_select_local_clears_state_and_restores_pin(env_file: Path) -> None:
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))
    _select(session, env_file, "openai")
    out = _select(session, env_file, "local")
    assert out["active"] is True
    assert not (env_file.parent / "data" / "run" / "ai-provider.json").exists()
    env_text = env_file.read_text()
    assert "KP_WORKER_AI_MODEL_ID" in env_text and "qwen-local" in env_text
    assert session.store["openai"].is_active is False


def test_select_aggregator_requires_a_model_id(env_file: Path) -> None:
    session = _Session()
    # openrouter has no default model; a key alone is not enough.
    session.add(AiGenerationProvider(provider="openrouter", api_key="sk-or", model_id=None, is_active=False))
    with pytest.raises(ValidationError_):
        _select(session, env_file, "openrouter")


def test_select_custom_requires_a_base_url(env_file: Path) -> None:
    session = _Session()
    # custom needs no key, but a self-hosted endpoint has no default base URL.
    session.add(AiGenerationProvider(provider="custom", api_key=None, model_id="dolphin-llama3", is_active=False))
    with pytest.raises(ValidationError_):
        _select(session, env_file, "custom")


def test_select_custom_local_no_key_uses_auth_none(env_file: Path) -> None:
    session = _Session()
    session.add(
        AiGenerationProvider(
            provider="custom",
            api_key=None,
            model_id="huihui/llama3.3-abliterated",
            base_url="http://127.0.0.1:11434/v1",
            is_active=False,
        )
    )
    out = _select(session, env_file, "custom")
    assert out["active"] is True
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state["provider"] == "custom"
    assert state["base_url"] == "http://127.0.0.1:11434/v1"
    assert state["model_id"] == "huihui/llama3.3-abliterated"
    assert state["api_key"] == ""
    assert state["auth_style"] == "none"


def test_switch_between_two_hosted_providers_leaves_one_active(env_file: Path) -> None:
    session = _Session()
    session.add(AiGenerationProvider(provider="openrouter", api_key="k1", model_id="m/one", is_active=False))
    session.add(AiGenerationProvider(provider="opencode", api_key="k2", model_id="m/two", is_active=False))
    _select(session, env_file, "openrouter")
    _select(session, env_file, "opencode")
    actives = [p for p, r in session.store.items() if r.is_active]
    assert actives == ["opencode"]
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state["provider"] == "opencode" and state["model_id"] == "m/two"
