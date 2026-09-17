"""Unit tests for the console model-residency control seam.

These cover the fail-closed and gating behavior of the swap action directly,
independent of the full FastAPI wiring (which the route-authorization inventory
pins separately): unknown targets never reach a shell, a missing swap script
fails closed, managed configuration is rejected, and every attempt is audited.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from kp_operator_api.console import model_control as mc
from kp_operator_api.console.model_control import ModelSwapRequest, model_control_status, model_control_swap
from kp_telemetry.errors import ConflictError


def _request(config_is_managed: bool) -> SimpleNamespace:
    settings = SimpleNamespace(config_is_managed=config_is_managed)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))


def _principal() -> SimpleNamespace:
    return SimpleNamespace(principal_id="admin-0000")


def test_swap_rejects_unknown_target_without_shelling_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mc, "_swap_script_present", lambda: True)
    run = Mock()
    monkeypatch.setattr(mc.subprocess, "run", run)
    audit = Mock()
    with pytest.raises(HTTPException) as exc:
        model_control_swap(
            ModelSwapRequest(target="reboot"),
            _request(False),
            audit=audit,
            session=Mock(),
            principal=_principal(),
        )
    assert exc.value.status_code == 400
    run.assert_not_called()


def test_swap_fails_closed_when_script_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mc, "_swap_script_present", lambda: False)
    run = Mock()
    monkeypatch.setattr(mc.subprocess, "run", run)
    audit = Mock()
    result = model_control_swap(
        ModelSwapRequest(target="qwen"),
        _request(False),
        audit=audit,
        session=Mock(),
        principal=_principal(),
    )
    assert result.ok is False
    run.assert_not_called()
    audit.record.assert_called_once()


def test_swap_success_runs_script_and_audits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mc, "_swap_script_present", lambda: True)
    monkeypatch.setattr(
        mc.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="done\n", stderr=""),
    )
    audit = Mock()
    result = model_control_swap(
        ModelSwapRequest(target="aggregate"),
        _request(False),
        audit=audit,
        session=Mock(),
        principal=_principal(),
    )
    assert result.ok is True
    assert result.target == "aggregate"
    audit.record.assert_called_once()


def test_swap_rejects_managed_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mc, "_swap_script_present", lambda: True)
    run = Mock()
    monkeypatch.setattr(mc.subprocess, "run", run)
    with pytest.raises(ConflictError):
        model_control_swap(
            ModelSwapRequest(target="qwen"),
            _request(True),
            audit=Mock(),
            session=Mock(),
            principal=_principal(),
        )
    run.assert_not_called()


def test_status_reports_disabled_when_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    llama = Mock()
    monkeypatch.setattr(mc, "_llama_loaded", llama)
    status = model_control_status(_request(True), _principal=_principal())
    assert status.enabled is False
    llama.assert_not_called()


def test_qwen_loaded_parses_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mc.httpx,
        "get",
        lambda *args, **kwargs: SimpleNamespace(status_code=200, json=lambda: {"models": [{"name": "qwen3:32b"}]}),
    )
    assert mc._qwen_loaded() is True


def test_llama_loaded_on_health_200(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mc.httpx,
        "get",
        lambda *args, **kwargs: SimpleNamespace(status_code=200),
    )
    assert mc._llama_loaded() is True
