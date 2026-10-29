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
from kp_database.models import AiGenerationProvider, ProviderConfigGeneration
from kp_operator_api import ai_providers as registry
from kp_operator_api.console import ai_providers as ai_providers_module
from kp_operator_api.console.ai_providers import (
    ProviderConfigApplyError,
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
        self.generation_row: ProviderConfigGeneration | None = None
        self.commits = 0

    def get(self, model: object, identifier: object) -> Any:
        if model is ProviderConfigGeneration:
            return self.generation_row
        return self.store.get(identifier)

    def add(self, row: Any) -> None:
        if isinstance(row, ProviderConfigGeneration):
            self.generation_row = row
        else:
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


def test_classify_egress_from_base_url_host() -> None:
    # R-02: egress is derived from the actual base URL host, not a preset guess.
    assert registry.classify_egress("http://127.0.0.1:11434/v1") == registry.EGRESS_ON_NETWORK
    assert registry.classify_egress("http://192.168.1.24:11434/v1") == registry.EGRESS_ON_NETWORK
    assert registry.classify_egress("http://ollama.local/v1") == registry.EGRESS_ON_NETWORK
    assert registry.classify_egress("https://api.openai.com/v1") == registry.EGRESS_OFFSITE
    assert registry.classify_egress("https://8.8.8.8/v1") == registry.EGRESS_OFFSITE
    assert registry.classify_egress("") == registry.EGRESS_UNKNOWN
    assert registry.classify_egress("http://") == registry.EGRESS_UNKNOWN
    # local is on-network by construction; a public custom URL is honestly offsite.
    assert registry.provider_egress("local", None) == registry.EGRESS_ON_NETWORK
    assert registry.provider_egress("custom", "http://127.0.0.1:11434/v1") == registry.EGRESS_ON_NETWORK
    assert registry.provider_egress("custom", "https://api.example.com/v1") == registry.EGRESS_OFFSITE


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
    assert out["generation"] == 1
    # state file written for the gateway, stamped with the committed generation
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state == {
        "provider": "openai",
        "base_url": "https://api.openai.com/v1",
        "model_id": "gpt-4o",
        "generation": 1,
        "api_key": "sk-secret",
        "auth_style": "bearer",
    }
    # authoritative generation marker written as the on-disk shadow of the DB
    marker = json.loads((env_file.parent / "data" / "run" / "ai-provider.generation").read_text())
    assert marker == {"generation": 1, "provider": "openai"}
    # generation committed AND applied (no blocked drift once verified)
    assert session.generation_row is not None
    assert session.generation_row.generation == 1
    assert session.generation_row.applied_generation == 1
    assert session.generation_row.active_provider == "openai"
    # worker model pin repinned, local pin snapshotted for restore, restart signalled
    env_text = env_file.read_text()
    assert "KP_WORKER_AI_MODEL_ID" in env_text and "gpt-4o" in env_text
    assert session.store["local"].model_id == "qwen-local"
    assert session.store["openai"].is_active is True
    assert (env_file.parent / "data" / "run" / "restart").exists()


def test_select_records_truthful_egress(env_file: Path) -> None:
    # R-02: the immutable ai-provider.select audit detail reflects the ACTUAL
    # base URL, not the static preset flag — a custom provider pointed at the
    # public internet must record offsite, and a loopback one on-network.
    for base_url, expect_egress, expect_offsite in (
        ("https://api.example.com/v1", registry.EGRESS_OFFSITE, True),
        ("http://127.0.0.1:11434/v1", registry.EGRESS_ON_NETWORK, False),
    ):
        session = _Session()
        session.add(AiGenerationProvider(provider="custom", base_url=base_url, model_id="m", is_active=False))
        audit = _Audit()
        select_ai_provider(
            ProviderSelectRequest(provider="custom"),
            request=_request(env_file),  # type: ignore[arg-type]
            session=session,  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            settings=_settings(env_file),
            principal=_principal(),
        )
        detail = audit.events[0]["detail"]
        assert detail["egress"] == expect_egress
        assert detail["sends_data_offsite"] is expect_offsite


def test_select_local_clears_state_and_restores_pin(env_file: Path) -> None:
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))
    _select(session, env_file, "openai")
    out = _select(session, env_file, "local")
    assert out["active"] is True
    assert out["generation"] == 2
    assert not (env_file.parent / "data" / "run" / "ai-provider.json").exists()
    # marker advanced to the local selection; a stale external state file would
    # be ignored by the gateway (it serves local).
    marker = json.loads((env_file.parent / "data" / "run" / "ai-provider.generation").read_text())
    assert marker == {"generation": 2, "provider": "local"}
    assert session.generation_row is not None and session.generation_row.applied_generation == 2
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
    assert state["generation"] == 1


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
    # generation bumped once per selection
    assert session.generation_row is not None and session.generation_row.generation == 2


# --- W1-04: generation token, blocked drift, plaintext minimization ----------


def test_side_effect_fault_leaves_blocked_drift_and_detectable_marker(env_file: Path, monkeypatch) -> None:
    """Acceptance 1: a post-commit side-effect fault leaves an explicit blocked
    drift (committed generation ahead of applied) and an on-disk marker the
    gateway detects as a stale generation — never a silent half-applied config."""
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))

    # The marker is written FIRST; make the state-file write fault AFTER it, so
    # the marker is at the new generation while the state file is not.
    def _boom(*_a: Any, **_k: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(ai_providers_module, "_write_state_file", _boom)
    with pytest.raises(ProviderConfigApplyError):
        _select(session, env_file, "openai")

    # DB: committed generation is 1, but applied stayed at 0 -> blocked drift.
    assert session.generation_row is not None
    assert session.generation_row.generation == 1
    assert session.generation_row.applied_generation == 0
    # Marker advanced to generation 1 while the state file was never written:
    # the gateway reconcile sees marker(1)/state(absent) and fails closed.
    marker = json.loads((env_file.parent / "data" / "run" / "ai-provider.generation").read_text())
    assert marker == {"generation": 1, "provider": "openai"}
    assert not (env_file.parent / "data" / "run" / "ai-provider.json").exists()


def test_verify_detects_state_generation_mismatch(env_file: Path, monkeypatch) -> None:
    """A state file that lands at the wrong generation fails verification and
    keeps the DB in blocked drift (defence in depth over the marker ordering)."""
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))

    real_write = ai_providers_module._write_state_file

    def _write_stale(settings: Any, payload: dict[str, Any]) -> None:
        payload = {**payload, "generation": 999}  # wrong generation
        real_write(settings, payload)

    monkeypatch.setattr(ai_providers_module, "_write_state_file", _write_stale)
    with pytest.raises(ProviderConfigApplyError):
        _select(session, env_file, "openai")
    assert session.generation_row is not None and session.generation_row.applied_generation == 0


def test_env_secret_reference_omits_plaintext_key(env_file: Path) -> None:
    """Acceptance 3: when the deployment provides the provider key via the
    environment reference, the state file carries the reference and NO plaintext
    key; the 0600 plaintext fallback is used only when the reference is absent."""
    env_file.write_text("KP_WORKER_AI_MODEL_ID=qwen-local\nKP_AI_GATEWAY_PROVIDER_API_KEY=sk-from-env\n")
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))
    _select(session, env_file, "openai")
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state["auth_style"] == "bearer"
    assert state.get("api_key_env") == "KP_AI_GATEWAY_PROVIDER_API_KEY"
    assert "api_key" not in state  # plaintext key never written to disk


def test_plaintext_key_fallback_when_no_env_reference(env_file: Path) -> None:
    """Without the env reference (no secret backend) the 0600 plaintext key is
    the documented fallback."""
    session = _Session()
    session.add(AiGenerationProvider(provider="openai", api_key="sk-secret", model_id="gpt-4o", is_active=False))
    _select(session, env_file, "openai")
    state = json.loads((env_file.parent / "data" / "run" / "ai-provider.json").read_text())
    assert state["api_key"] == "sk-secret"
    assert "api_key_env" not in state
