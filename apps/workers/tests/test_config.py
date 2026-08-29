import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from kp_workers.config import WorkerSettings
from pydantic import ValidationError

TENANT_ID = "11111111-1111-4111-8111-111111111111"
DIRECTORY_CLIENT_ID = "22222222-2222-4222-8222-222222222222"
MAILBOX_CLIENT_ID = "33333333-3333-4333-8333-333333333333"
ANCHOR_CLIENT_ID = "55555555-5555-4555-8555-555555555555"
GROUP_ID = "44444444-4444-4444-8444-444444444444"

_VALID_MANAGED_ROLE_CONFIG: dict[str, dict[str, object]] = {
    "audit-anchor": {
        "audit_anchor_container_url": "https://auditaccount.blob.core.windows.net/audit-head-anchors",
        "audit_anchor_client_id": ANCHOR_CLIENT_ID,
    },
    "ingestion": {},
    "generation": {
        "ai_base_url": "https://ai.internal.example/v1",
        "training_base_url": "https://training.example/awareness",
        "ai_model_id": "llama.cpp/Qwen3-8B-Q4_K_M-v1",
    },
    "delivery": {
        "smtp_address": "smtp.example:587",
        "smtp_sender": "security@example.com",
        "tracking_base_url": "https://track.example",
        "training_base_url": "https://training.example/awareness",
    },
    "retention": {
        "awareness_pseudonym_key": "44" * 32,
        "awareness_pseudonym_key_version": "retention-v1",
    },
    "mailbox": {
        "reported_mailbox_url": "https://graph.microsoft.com/v1.0",
        "reported_mailbox_provider": "microsoft365",
        "reported_mailbox_client_id": MAILBOX_CLIENT_ID,
        "reported_mailbox_id": "reports@example.com",
        "microsoft_tenant_id": TENANT_ID,
    },
    "reminder": {
        "smtp_address": "smtp.example:587",
        "smtp_sender": "security@example.com",
        "tracking_base_url": "https://track.example",
        "training_base_url": "https://training.example/awareness",
        "training_token_hmac_key": "33" * 32,
    },
    "alert": {},
    "directory": {
        "graph_base_url": "https://graph.microsoft.com/v1.0",
        "graph_client_id": DIRECTORY_CLIENT_ID,
        "graph_group_ids": GROUP_ID,
        "microsoft_tenant_id": TENANT_ID,
    },
}


def _settings(**overrides: object) -> WorkerSettings:
    values: dict[str, object] = {
        "_env_file": None,
        "ai_base_url": None,
        "graph_base_url": None,
        "graph_client_id": None,
        "graph_group_ids": "",
        "microsoft_tenant_id": None,
        "reported_mailbox_url": None,
        "reported_mailbox_client_id": None,
        "reported_mailbox_id": None,
        "reported_mailbox_bearer_token": None,
        "reported_mailbox_basic_username": None,
        "reported_mailbox_basic_password": None,
        "training_token_hmac_key": "",
        "acs_client_id": None,
        "smtp_address": None,
        "smtp_username": None,
        "smtp_password": None,
        "smtp_sender": None,
        "tracking_base_url": "http://localhost:8001",
        "training_base_url": "http://127.0.0.1:8001/v1/training/awareness",
    }
    values.update(overrides)
    return WorkerSettings(**values)


@pytest.mark.parametrize("runtime_mode", ["managed", "production"])
@pytest.mark.parametrize("worker_name", sorted(_VALID_MANAGED_ROLE_CONFIG))
def test_every_worker_role_accepts_its_valid_managed_configuration(worker_name: str, runtime_mode: str) -> None:
    settings = _settings(
        worker_name=worker_name,
        runtime_mode=runtime_mode,
        **_VALID_MANAGED_ROLE_CONFIG[worker_name],
    )

    assert settings.worker_name == worker_name
    assert settings.runtime_mode == runtime_mode


@pytest.mark.parametrize("worker_name", ["ingestion", "alert"])
def test_managed_workers_do_not_require_unrelated_provider_configuration(worker_name: str) -> None:
    settings = _settings(worker_name=worker_name, runtime_mode="managed")

    assert settings.worker_name == worker_name


def test_retired_runtime_drift_settings_are_not_worker_settings() -> None:
    assert "reminder_after_hours" not in WorkerSettings.model_fields
    assert "queue_prefix" not in WorkerSettings.model_fields
    example = (Path(__file__).resolve().parents[3] / ".env.example").read_text(encoding="utf-8")
    assert "KP_WORKER_REMINDER_AFTER_HOURS=" not in example
    assert "KP_WORKER_QUEUE_PREFIX=" not in example


def test_ai_model_id_rejects_control_characters() -> None:
    with pytest.raises(ValidationError, match="single line without control characters"):
        _settings(worker_name="generation", ai_model_id="model\x00id")
    with pytest.raises(ValidationError, match="single line without control characters"):
        _settings(worker_name="generation", ai_model_id="model\nid")


def test_managed_generation_requires_a_pinned_model_identity() -> None:
    base = {
        "worker_name": "generation",
        "runtime_mode": "managed",
        "ai_base_url": "https://ai.internal.example/v1",
        "training_base_url": "https://training.example/awareness",
    }
    with pytest.raises(ValidationError, match="AI model ID is required"):
        _settings(**base)
    settings = _settings(**base, ai_model_id="llama.cpp/Qwen3-8B-Q4_K_M-v1")
    assert settings.ai_model_id == "llama.cpp/Qwen3-8B-Q4_K_M-v1"


def test_development_generation_allows_an_unpinned_model() -> None:
    settings = _settings(
        worker_name="generation",
        runtime_mode="development",
        ai_base_url="http://mock-ai:8282",
        training_base_url="https://training.example/awareness",
    )
    assert settings.ai_model_id is None


@pytest.mark.parametrize(
    ("worker_name", "expected_message"),
    [
        ("generation", "AI base URL is required"),
        ("delivery", "tracking base URL must use a non-local HTTPS endpoint"),
        ("mailbox", "reported mailbox URL is required"),
        ("reminder", "tracking base URL must use a non-local HTTPS endpoint"),
        ("directory", "Graph base URL is required"),
    ],
)
def test_managed_provider_workers_reject_missing_configuration(worker_name: str, expected_message: str) -> None:
    with pytest.raises(ValidationError, match=expected_message):
        _settings(worker_name=worker_name, runtime_mode="managed")


def test_managed_audit_anchor_rejects_missing_or_non_azure_configuration() -> None:
    with pytest.raises(ValidationError, match="identify one Azure Blob container"):
        _settings(worker_name="audit-anchor", runtime_mode="managed")
    with pytest.raises(ValidationError, match="identify one Azure Blob container"):
        _settings(
            worker_name="audit-anchor",
            runtime_mode="managed",
            audit_anchor_container_url="https://storage.example/anchors",
            audit_anchor_client_id=ANCHOR_CLIENT_ID,
        )
    with pytest.raises(ValidationError, match="complete UUID"):
        _settings(
            worker_name="audit-anchor",
            runtime_mode="managed",
            audit_anchor_container_url="https://auditaccount.blob.core.windows.net/audit-head-anchors",
            audit_anchor_client_id="system-assigned",
        )


def test_managed_graph_roles_require_distinct_explicit_identity_client_ids() -> None:
    with pytest.raises(ValidationError, match="distinct managed identity client IDs"):
        _settings(
            worker_name="directory",
            runtime_mode="managed",
            graph_base_url="https://graph.microsoft.com/v1.0",
            graph_client_id=DIRECTORY_CLIENT_ID,
            graph_group_ids=GROUP_ID,
            microsoft_tenant_id=TENANT_ID,
            reported_mailbox_client_id=DIRECTORY_CLIENT_ID,
        )


def test_managed_directory_rejects_pasted_token_and_unscoped_user_collection() -> None:
    base = {
        "worker_name": "directory",
        "runtime_mode": "managed",
        "graph_base_url": "https://graph.microsoft.com/v1.0",
        "graph_client_id": DIRECTORY_CLIENT_ID,
        "microsoft_tenant_id": TENANT_ID,
    }
    with pytest.raises(ValidationError, match="selected-group synchronization"):
        _settings(**base)
    with pytest.raises(ValidationError, match="dedicated managed identity"):
        _settings(**base, graph_group_ids=GROUP_ID, graph_bearer_token="short-lived-token")


def test_managed_custom_graph_gateway_requires_declared_non_bearer_auth() -> None:
    base = {
        "worker_name": "directory",
        "runtime_mode": "managed",
        "graph_base_url": "https://directory-gateway.example/v1",
        "graph_client_id": DIRECTORY_CLIENT_ID,
        "graph_group_ids": GROUP_ID,
        "microsoft_tenant_id": TENANT_ID,
    }
    with pytest.raises(ValidationError, match="explicit API key"):
        _settings(**base)
    settings = _settings(**base, graph_api_key="gateway-secret")
    assert settings.graph_api_key == "gateway-secret"


def test_managed_mailbox_rejects_legacy_credentials() -> None:
    base = {
        "worker_name": "mailbox",
        "runtime_mode": "managed",
        **_VALID_MANAGED_ROLE_CONFIG["mailbox"],
    }
    with pytest.raises(ValidationError, match="dedicated managed identity"):
        _settings(**base, reported_mailbox_bearer_token="short-lived-token")


@pytest.mark.parametrize(
    ("worker_name", "overrides", "expected_message"),
    [
        (
            "generation",
            {
                "ai_base_url": "http://mock-ai:8282",
                "training_base_url": "https://training.example/awareness",
            },
            "AI base URL must use a non-local HTTPS endpoint",
        ),
        (
            "directory",
            {"graph_base_url": "http://mock-graph:8181"},
            "Graph base URL must use a non-local HTTPS endpoint",
        ),
        (
            "mailbox",
            {"reported_mailbox_url": "http://mailpit:8025"},
            "reported mailbox URL must use a non-local HTTPS endpoint",
        ),
        (
            "delivery",
            {
                "smtp_address": "smtp.example:587",
                "smtp_sender": "security@example.com",
                "tracking_base_url": "http://localhost:8001",
                "training_base_url": "https://training.example/awareness",
            },
            "tracking base URL must use a non-local HTTPS endpoint",
        ),
        (
            "reminder",
            {
                "smtp_address": "smtp.example:587",
                "smtp_sender": "security@example.com",
                "tracking_base_url": "https://track.example",
                "training_base_url": "http://127.0.0.1:8001/training",
            },
            "training base URL must use a non-local HTTPS endpoint",
        ),
    ],
)
def test_managed_provider_workers_reject_local_fallbacks(
    worker_name: str, overrides: dict[str, object], expected_message: str
) -> None:
    with pytest.raises(ValidationError, match=expected_message):
        _settings(worker_name=worker_name, runtime_mode="production", **overrides)


def test_managed_smtp_worker_requires_explicit_non_local_tls_configuration() -> None:
    base = {
        "_env_file": None,
        "worker_name": "delivery",
        "runtime_mode": "managed",
        "smtp_sender": "security@example.com",
        "tracking_base_url": "https://track.example",
        "training_base_url": "https://training.example/awareness",
    }

    with pytest.raises(ValidationError, match="SMTP address is required"):
        _settings(**base)
    with pytest.raises(ValidationError, match="SMTP address must use a non-local host"):
        _settings(**base, smtp_address="localhost:1025")
    with pytest.raises(ValidationError, match="SMTP must use SSL or STARTTLS"):
        _settings(**base, smtp_address="smtp.example:25", smtp_starttls=False)


def test_managed_delivery_accepts_azure_communication_services_without_smtp() -> None:
    checked_at = datetime.now(UTC).isoformat()
    settings = _settings(
        worker_name="delivery",
        runtime_mode="managed",
        email_provider="azure_communication_services",
        acs_email_endpoint="https://mailer.communication.azure.com",
        acs_client_id="66666666-6666-4666-8666-666666666666",
        smtp_sender="awareness@mail.example.com",
        acs_sending_domain="mail.example.com",
        acs_sender_local_part="awareness",
        acs_sender_display_name="Security Awareness",
        acs_domain_verification_status="verified",
        acs_spf_verification_status="verified",
        acs_dkim_verification_status="verified",
        acs_dkim2_verification_status="verified",
        acs_sender_username_status="verified",
        acs_readiness_checked_at=checked_at,
        acs_daily_message_limit=1000,
        acs_messages_per_minute=20,
        acs_ramp_batch_size=10,
        acs_ramp_interval_seconds=60,
        acs_receipt_signing_key="12" * 32,
        tracking_base_url="https://track.example",
        training_base_url="https://training.example/awareness",
    )

    assert settings.email_provider == "azure_communication_services"
    assert settings.smtp_address is None


def _managed_acs_values() -> dict[str, object]:
    return {
        "worker_name": "delivery",
        "runtime_mode": "managed",
        "email_provider": "azure_communication_services",
        "acs_email_endpoint": "https://mailer.communication.azure.com",
        "acs_client_id": "66666666-6666-4666-8666-666666666666",
        "smtp_sender": "awareness@mail.example.com",
        "acs_sending_domain": "mail.example.com",
        "acs_sender_local_part": "awareness",
        "acs_sender_display_name": "Security Awareness",
        "acs_domain_verification_status": "verified",
        "acs_spf_verification_status": "verified",
        "acs_dkim_verification_status": "verified",
        "acs_dkim2_verification_status": "verified",
        "acs_sender_username_status": "verified",
        "acs_readiness_checked_at": datetime.now(UTC).isoformat(),
        "acs_daily_message_limit": 1000,
        "acs_messages_per_minute": 20,
        "acs_ramp_batch_size": 10,
        "acs_ramp_interval_seconds": 60,
        "acs_receipt_signing_key": "12" * 32,
        "tracking_base_url": "https://track.example",
        "training_base_url": "https://training.example/awareness",
    }


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"acs_sending_domain": "mailer.azurecomm.net", "smtp_sender": "awareness@mailer.azurecomm.net"},
            "customer-managed",
        ),
        ({"smtp_sender": "other@mail.example.com"}, "must match"),
        ({"acs_dkim2_verification_status": "pending"}, "must all be verified"),
        ({"acs_messages_per_minute": 2000, "acs_daily_message_limit": 1000}, "cannot exceed"),
        ({"acs_ramp_batch_size": 21}, "ramp batch"),
        ({"acs_email_connection_string": "endpoint=secret"}, "managed identity"),
        ({"acs_client_id": None}, "ACS sending managed identity client ID"),
        ({"acs_receipt_signing_key": "not-a-key"}, "ACS_RECEIPT_SIGNING_KEY"),
    ],
)
def test_managed_acs_rejects_fallback_identity_and_invalid_readiness(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _settings(**{**_managed_acs_values(), **override})


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://attacker.example",
        "https://mailer.communication.azure.com.attacker.example",
        "https://communication.azure.com",
        "https://nested.mailer.communication.azure.com",
        "https://mailer.communication.azure.com:444",
        "https://mailer.communication.azure.com/private",
        "https://mailer.communication.azure.com./",
        "https://operator:secret@mailer.communication.azure.com",
        "https://mailer.communication.azure.com?redirect=attacker.example",
    ],
)
def test_managed_acs_rejects_unapproved_data_plane_endpoints(endpoint: str) -> None:
    with pytest.raises(ValidationError, match=r"ACS email endpoint must (?:be|use)"):
        _settings(**{**_managed_acs_values(), "acs_email_endpoint": endpoint})


def test_managed_acs_accepts_explicit_standard_tls_port() -> None:
    settings = _settings(
        **{**_managed_acs_values(), "acs_email_endpoint": "https://mailer.communication.azure.com:443"}
    )

    assert settings.acs_email_endpoint == "https://mailer.communication.azure.com:443"


def test_managed_acs_rechecks_evidence_age_when_sender_is_used() -> None:
    settings = _settings(**_managed_acs_values())
    stale = datetime.now(UTC) + timedelta(hours=settings.acs_readiness_max_age_hours + 1)

    with pytest.raises(ValueError, match="stale"):
        settings.require_acs_delivery_ready(now=stale)


def test_managed_reminder_requires_dedicated_training_key() -> None:
    with pytest.raises(ValidationError, match="KP_WORKER_TRAINING_TOKEN_HMAC_KEY is required"):
        _settings(
            worker_name="reminder",
            runtime_mode="managed",
            smtp_address="smtp.example:587",
            smtp_sender="security@example.com",
            tracking_base_url="https://track.example",
            training_base_url="https://training.example/awareness",
        )


def test_training_key_must_be_256_bit_hex() -> None:
    settings = _settings(training_token_hmac_key="not-hex")
    with pytest.raises(RuntimeError, match="256-bit hex key"):
        settings.require_training_token_hmac_key()


def test_managed_delivery_rejects_local_azure_communication_services_endpoint() -> None:
    with pytest.raises(ValidationError, match=r"approved HTTPS \*\.communication\.azure\.com"):
        _settings(
            worker_name="delivery",
            runtime_mode="managed",
            email_provider="azure_communication_services",
            acs_email_endpoint="http://localhost:8080",
            smtp_sender="security@example.com",
            tracking_base_url="https://track.example",
            training_base_url="https://training.example/awareness",
        )


def test_local_development_retains_mock_provider_defaults() -> None:
    for worker_name in _VALID_MANAGED_ROLE_CONFIG:
        settings = _settings(worker_name=worker_name, runtime_mode="development")
        assert settings.effective_ai_base_url == "http://localhost:8282"
        assert settings.effective_graph_base_url == "http://localhost:8181"
        assert settings.effective_reported_mailbox_url == "http://localhost:8025"


@pytest.mark.parametrize("variable", ["KP_WORKER_RUNTIME_MODE", "KP_WORKER_DEPLOYMENT_MODE"])
def test_runtime_mode_environment_aliases_are_supported(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    monkeypatch.delenv("KP_WORKER_RUNTIME_MODE", raising=False)
    monkeypatch.delenv("KP_WORKER_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv(variable, "managed")

    settings = _settings(worker_name="alert")

    assert settings.runtime_mode == "managed"


def test_validation_diagnostics_hide_secret_configuration_inputs() -> None:
    secret = "password=do-not-render https://provider.invalid/private/key.pem"

    with pytest.raises(ValidationError) as captured:
        _settings(
            smtp_username="operator",
            smtp_password=secret,
            smtp_ssl=True,
            smtp_starttls=True,
            graph_api_key=secret,
            database_url=f"postgresql+psycopg://worker:{secret}@db.invalid/app",
        )

    rendered = f"{captured.value!s}\n{captured.value!r}"
    assert secret not in rendered
    assert "provider.invalid" not in rendered
    assert "private/key.pem" not in rendered
    assert "SMTP SSL and STARTTLS cannot both be enabled" in rendered


def test_nested_managed_key_validation_has_no_exception_chain_or_secret_input() -> None:
    secret = "not-hex-password=do-not-render"

    with pytest.raises(ValidationError) as captured:
        _settings(
            worker_name="reminder",
            runtime_mode="managed",
            smtp_address="smtp.example:587",
            smtp_sender="security@example.com",
            tracking_base_url="https://track.example",
            training_base_url="https://training.example/awareness",
            training_token_hmac_key=secret,
        )

    rendered = f"{captured.value!s}\n{captured.value!r}"
    assert secret not in rendered
    assert "must be a 256-bit hex key" in rendered
    assert captured.value.__cause__ is None


def test_malformed_provider_url_diagnostic_does_not_echo_secret_port() -> None:
    secret = "password-do-not-render"

    with pytest.raises(ValidationError) as captured:
        _settings(graph_base_url=f"https://graph.example:{secret}/private/key.pem")

    rendered = f"{captured.value!s}\n{captured.value!r}"
    assert "Graph base URL must be HTTPS" in rendered
    assert secret not in rendered
    assert "private/key.pem" not in rendered
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("field", "url"),
    [
        ("graph_base_url", "https://user:SECRET_URL_TOKEN@graph.example/private/key.pem"),
        ("ai_base_url", "https://ai.example/private/key.pem?api_key=SECRET_URL_TOKEN"),
        ("reported_mailbox_url", "https://mail.example/private/key.pem;token=SECRET_URL_TOKEN"),
        ("acs_email_endpoint", "https://mailer.example/private/key.pem#SECRET_URL_TOKEN"),
        ("mock_graph_url", "http://localhost:8181/private/key.pem?token=SECRET_URL_TOKEN"),
        ("mock_ai_url", "http://mock-ai:8282/private/key.pem?token=SECRET_URL_TOKEN"),
        ("mailpit_api_url", "http://mailpit:8025/private/key.pem?token=SECRET_URL_TOKEN"),
        ("tracking_base_url", "https://track.example/private/key.pem?token=SECRET_URL_TOKEN"),
        ("training_base_url", "https://training.example/private/key.pem?token=SECRET_URL_TOKEN"),
    ],
)
def test_provider_base_urls_reject_embedded_credentials_and_parameters_without_echo(field: str, url: str) -> None:
    with pytest.raises(ValidationError) as captured:
        _settings(**{field: url})

    rendered = f"{captured.value!s}\n{captured.value!r}\n{''.join(traceback.format_exception(captured.value))}"
    assert "must be HTTPS without credentials, query parameters, or fragments" in rendered
    assert "SECRET_URL_TOKEN" not in rendered
    assert "private/key.pem" not in rendered
    assert "input_value=" not in rendered
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("field", "method"),
    [
        ("audit_hmac_key", "require_hmac"),
        ("roe_signing_key", "require_roe_signing_key"),
        ("ciphertext_kek", "require_kek"),
        ("recipient_hash_salt", "require_recipient_hash_salt"),
        ("training_token_hmac_key", "require_training_token_hmac_key"),
        ("acs_receipt_signing_key", "require_acs_receipt_signing_key"),
        ("awareness_pseudonym_key", "require_awareness_pseudonym_config"),
    ],
)
def test_secret_parser_failures_suppress_low_level_exception_chains(field: str, method: str) -> None:
    secret = "password=not-hex/private/key.pem"
    settings = _settings(**{field: secret})

    with pytest.raises(RuntimeError) as captured:
        getattr(settings, method)()

    assert secret not in str(captured.value)
    assert "private/key.pem" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_local_retention_uses_deterministic_synthetic_pseudonym_configuration() -> None:
    first = _settings(worker_name="retention")
    second = _settings(worker_name="retention")

    assert first.require_awareness_pseudonym_config() == second.require_awareness_pseudonym_config()
    key, version = first.require_awareness_pseudonym_config()
    assert len(key) == 32
    assert version == "synthetic-local-v1"
    example = (Path(__file__).resolve().parents[3] / ".env.example").read_text(encoding="utf-8")
    assert f"KP_WORKER_AWARENESS_PSEUDONYM_KEY={key.hex()}" in example
    assert f"KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION={version}" in example


def test_managed_retention_fails_closed_without_dedicated_pseudonym_configuration() -> None:
    with pytest.raises(ValidationError, match="KP_WORKER_AWARENESS_PSEUDONYM_KEY must be"):
        _settings(worker_name="retention", runtime_mode="managed")
    with pytest.raises(ValidationError, match="KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION"):
        _settings(
            worker_name="retention",
            runtime_mode="managed",
            awareness_pseudonym_key="44" * 32,
        )


@pytest.mark.parametrize(
    ("key", "version"),
    [
        ("44" * 31, "v1"),
        ("4" * 65, "v1"),
        ("44" * 65, "v1"),
        ("AA" * 32, "v1"),
        ("44" * 32, "contains spaces"),
        ("44" * 32, "a" * 33),
    ],
)
def test_awareness_pseudonym_configuration_is_strict_bounded_and_secret_safe(key: str, version: str) -> None:
    with pytest.raises((RuntimeError, ValidationError)) as captured:
        settings = _settings(
            awareness_pseudonym_key=key,
            awareness_pseudonym_key_version=version,
        )
        settings.require_awareness_pseudonym_config()

    rendered = f"{captured.value!s}\n{captured.value!r}"
    assert key not in rendered
    assert "input_value=" not in rendered


def test_awareness_pseudonym_configuration_accepts_at_least_32_bounded_bytes() -> None:
    settings = _settings(
        awareness_pseudonym_key="44" * 33,
        awareness_pseudonym_key_version="v2.1",
    )

    key, version = settings.require_awareness_pseudonym_config()
    assert key == b"D" * 33
    assert version == "v2.1"


def test_worker_ciphertext_keyring_supports_bounded_decrypt_only_rotation_keys() -> None:
    settings = _settings(
        ciphertext_kek="aa" * 32,
        ciphertext_key_id="active-2",
        ciphertext_prior_keys=f"retired-1={'11' * 32},retired_0={'22' * 32}",
    )

    key_id, active_key, prior_keys = settings.require_cipher_keyring()

    assert key_id == "active-2"
    assert active_key == b"\xaa" * 32
    assert prior_keys == {"retired-1": b"\x11" * 32, "retired_0": b'"' * 32}


@pytest.mark.parametrize(
    "overrides",
    [
        {"ciphertext_key_id": "invalid.key/id"},
        {"ciphertext_prior_keys": "missing-separator"},
        {"ciphertext_prior_keys": "primary=" + "11" * 32},
        {"ciphertext_prior_keys": "old=" + "aa" * 32},
        {"ciphertext_prior_keys": ",".join(f"old{index}={'11' * 32}" for index in range(5))},
    ],
)
def test_worker_ciphertext_keyring_rejects_invalid_rotation_configuration_without_echo(
    overrides: dict[str, str],
) -> None:
    settings = _settings(ciphertext_kek="aa" * 32, **overrides)

    with pytest.raises(RuntimeError) as caught:
        settings.require_cipher_keyring()

    rendered = "".join(traceback.format_exception(caught.value))
    assert "invalid.key/id" not in rendered
    assert "aa" * 32 not in rendered
    assert caught.value.__cause__ is None


def test_worker_ciphertext_prior_key_parser_redacts_malformed_key_material() -> None:
    secret = "password=not-hex/private/key.pem"
    settings = _settings(ciphertext_kek="aa" * 32, ciphertext_prior_keys=f"old={secret}")

    with pytest.raises(RuntimeError) as caught:
        settings.require_cipher_keyring()

    rendered = "".join(traceback.format_exception(caught.value))
    assert secret not in rendered
    assert "private/key.pem" not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
