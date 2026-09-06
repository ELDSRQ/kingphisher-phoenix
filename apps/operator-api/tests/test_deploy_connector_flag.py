"""ARC-002 Item 1 Phase 1: the ``deploy_connector_enabled`` flag gate.

The in-operator-API Azure deploy / GitHub-dispatch connector is gated behind a
single additive, reversible flag. These tests pin the two invariants the change
must hold:

* Default (flag ON) is byte-identical to before the flag existed: every Azure
  deployment route stays reachable and the public ``auth-mode`` hint is
  unchanged (no extra key), so the console Deployment nav shows exactly as today.
* Flag OFF makes the whole Azure-deploy route surface respond 404 and withdraws
  the nav hint (``auth-mode`` reports ``deploy_connector_enabled: false``), yet
  the routes remain registered so flipping the flag back ON fully restores them.

No Azure capability is removed — only its visibility/activation is gated — so the
ability to flip an install between local-only and Azure is preserved.
"""

from __future__ import annotations

import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import create_app

KEK = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


class _FakeAuditStore:
    def record(self, actor, action, object_type, object_id, detail=None) -> None:  # noqa: D401
        pass

    def list_events(self, limit: int = 500) -> list[dict[str, object]]:
        return []


# Every Azure deploy / GitHub-dispatch route the connector owns, as
# (method, path, json-body-or-None). The path params are irrelevant because the
# gate fires before routing reaches the orchestrator.
_AZURE_ROUTES: tuple[tuple[str, str, dict | None], ...] = (
    ("GET", "/api/v1/console/azure-deployment", None),
    ("POST", "/api/v1/console/azure-deployment/validate", {"values": {}}),
    ("POST", "/api/v1/console/azure-deployment/orchestration/plan", {"values": {}}),
    ("GET", "/api/v1/console/azure-deployment/orchestration/latest", None),
    ("GET", "/api/v1/console/azure-deployment/orchestration/plans/plan-1", None),
    (
        "POST",
        "/api/v1/console/azure-deployment/orchestration/plans/plan-1/apply",
        {"confirm": True, "review_digest": "a" * 64, "rationale": "reviewed staging"},
    ),
    (
        "POST",
        "/api/v1/console/azure-deployment/orchestration/plans/plan-1/retry",
        {"confirm": True, "review_digest": "a" * 64, "rationale": "reviewed staging"},
    ),
    (
        "POST",
        "/api/v1/console/azure-deployment/orchestration/plans/plan-1/advance",
        {"confirm": True, "review_digest": "a" * 64},
    ),
)


@pytest.fixture()
def env_file(tmp_path) -> str:
    path = tmp_path / ".env"
    path.write_text("KP_CONSOLE_PASSWORD=correct-horse-battery-staple\n", encoding="utf-8")
    return str(path)


def _settings(env_file: str, *, deploy_connector_enabled: bool) -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key=HMAC,
        ciphertext_kek=KEK,
        console_jwt_secret=CONSOLE_JWT,
        env_file=env_file,
        oidc_issuer="http://localhost:8443/realms/kingphisher",
        oidc_audience="kp-operator-api",
        console_static_dir="/nonexistent-console-dir",
        deploy_connector_enabled=deploy_connector_enabled,
    )


def _app(settings: OperatorApiSettings):
    app = create_app(settings)
    app.state.audit_store = _FakeAuditStore()
    # Keep the unrelated audit-mutation gate healthy so the connector gate (not a
    # DB-less 503) is what these tests observe on the mutation routes.
    app.state.audit_health_check = lambda: True
    return app


def _admin_headers(settings: OperatorApiSettings) -> dict[str, str]:
    claims = {
        "sub": str(uuid.uuid4()),
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "exp": 2_000_000_000,
        "nbf": 0,
        "realm_access": {"roles": ["administrator"]},
    }
    token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def _call(client: TestClient, method: str, path: str, body: dict | None, headers: dict[str, str]):
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, headers=headers, json=body)


# --------------------------------------------------------------------------- #
# The flag defaults to ON and preserves today's behavior.
# --------------------------------------------------------------------------- #


def test_flag_defaults_to_enabled() -> None:
    # The whole safety of this change rests on the default: turning the surface
    # off must be a deliberate opt-in, never the out-of-the-box behavior.
    assert OperatorApiSettings.model_fields["deploy_connector_enabled"].default is True


def test_flag_on_keeps_azure_deployment_surface_reachable(env_file: str) -> None:
    settings = _settings(env_file, deploy_connector_enabled=True)
    assert settings.deploy_connector_enabled is True
    with TestClient(_app(settings)) as client:
        headers = _admin_headers(settings)
        # The schema route returns 200 exactly as before the flag existed.
        schema = client.get("/api/v1/console/azure-deployment", headers=headers)
        assert schema.status_code == 200, schema.text
        # The validate route still runs its validation (200 with an errors map),
        # rather than being gated away.
        validated = client.post(
            "/api/v1/console/azure-deployment/validate",
            headers=headers,
            json={"values": {}},
        )
        assert validated.status_code == 200, validated.text
        assert validated.json()["ok"] is False
        # None of the connector routes 404 when the flag is on.
        for method, path, body in _AZURE_ROUTES:
            assert _call(client, method, path, body, headers).status_code != 404, path


def test_flag_on_leaves_auth_mode_hint_byte_identical(env_file: str) -> None:
    settings = _settings(env_file, deploy_connector_enabled=True)
    with TestClient(_app(settings)) as client:
        body = client.get("/api/v1/console/auth-mode").json()
    # Byte-identical to today: exactly the two historical keys, and crucially NO
    # deploy_connector_enabled key, so the console shows the Deployment nav.
    assert body == {"auth_mode": "dev", "deployment_mode": "single_tenant"}


# --------------------------------------------------------------------------- #
# Flag OFF disables the routes and hides the nav.
# --------------------------------------------------------------------------- #


def test_flag_off_disables_every_azure_route(env_file: str) -> None:
    settings = _settings(env_file, deploy_connector_enabled=False)
    assert settings.deploy_connector_enabled is False
    with TestClient(_app(settings)) as client:
        headers = _admin_headers(settings)
        for method, path, body in _AZURE_ROUTES:
            response = _call(client, method, path, body, headers)
            assert response.status_code == 404, f"{method} {path} -> {response.status_code}"


def test_flag_off_withdraws_the_deployment_nav_hint(env_file: str) -> None:
    settings = _settings(env_file, deploy_connector_enabled=False)
    with TestClient(_app(settings)) as client:
        body = client.get("/api/v1/console/auth-mode").json()
    # The additive key the console reads to hide the Azure Deployment nav.
    assert body["deploy_connector_enabled"] is False
    assert body["auth_mode"] == "dev"
    assert body["deployment_mode"] == "single_tenant"


def test_flag_off_keeps_routes_registered_so_the_flip_is_reversible(env_file: str) -> None:
    # The gate is activation-only: the routes stay mounted while disabled, so
    # turning the flag back on restores the connector with no change to the API
    # surface. Prove it against the live OpenAPI path table of a disabled app.
    disabled = _app(_settings(env_file, deploy_connector_enabled=False))
    registered = set(disabled.openapi()["paths"])
    for _method, path, _body in _AZURE_ROUTES:
        openapi_path = path.replace("plan-1", "{plan_id}")
        assert openapi_path in registered, openapi_path


def test_toggling_the_flag_back_on_restores_the_surface(env_file: str) -> None:
    # Same env, only the flag differs: off -> 404, on -> reachable. This is the
    # reversibility invariant the local/Azure flip depends on.
    disabled = _settings(env_file, deploy_connector_enabled=False)
    with TestClient(_app(disabled)) as client:
        headers = _admin_headers(disabled)
        assert client.get("/api/v1/console/azure-deployment", headers=headers).status_code == 404

    enabled = _settings(env_file, deploy_connector_enabled=True)
    with TestClient(_app(enabled)) as client:
        headers = _admin_headers(enabled)
        assert client.get("/api/v1/console/azure-deployment", headers=headers).status_code == 200
