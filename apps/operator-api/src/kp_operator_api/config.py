"""Operator API configuration.

All values come from the environment. Secrets are never committed; the local
defaults in .env.example are for the disposable dev stack only.
"""

from __future__ import annotations

from typing import Literal

from kp_domain_models.policy import ApprovalPolicy, parse_domain_allowlist
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OperatorApiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OPERATOR_API_", env_file=".env", extra="ignore", populate_by_name=True
    )

    app_name: str = "kp-operator-api"
    deployment_mode: Literal["single_tenant"] = "single_tenant"
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    console_jwt_secret: str = ""
    recipient_hash_salt: str = ""
    oidc_mode: str = "dev"
    oidc_issuer: str = "http://localhost:8443/realms/kingphisher"
    oidc_audience: str = "kp-operator-api"
    oidc_client_id: str = "kp-operator-console"
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/v1/console/oidc/callback"
    oidc_scopes: str = "openid profile"
    log_level: str = "info"
    rate_limit_user_per_min: int = 120
    rate_limit_ip_per_min: int = 600
    max_body_bytes: int = 1_000_000
    redis_url: str = "redis://localhost:6379/0"
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://127.0.0.1:8001/v1/training/awareness"
    training_domains: str = "example.com,127.0.0.1"
    env_file: str = ".env"
    console_static_dir: str = "apps/operator-ui/src/console"

    # --- send-safety policy (T-06) ---
    # Both accept a shared, unprefixed env var so an operator sets one value
    # for the API and the workers instead of two that can silently diverge.
    approval_policy: ApprovalPolicy = Field(
        default=ApprovalPolicy.SINGLE_ADMIN,
        validation_alias=AliasChoices("OPERATOR_API_APPROVAL_POLICY", "OPERATOR_APPROVAL_POLICY"),
    )
    allowed_recipient_domains: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPERATOR_API_ALLOWED_RECIPIENT_DOMAINS",
            "KP_ALLOWED_RECIPIENT_DOMAINS",
        ),
    )
    #: Recipients per delivery message; bounds the 1MiB queue payload cap.
    delivery_batch_size: int = Field(default=200, ge=1, le=2000)

    @property
    def dev_auth_mode(self) -> bool:
        """True when running the offline dev-auth stack rather than real OIDC."""
        return self.oidc_mode == "dev"

    def recipient_domain_allowlist(self) -> frozenset[str]:
        return parse_domain_allowlist(self.allowed_recipient_domains)

    @model_validator(mode="after")
    def validate_approval_policy(self) -> OperatorApiSettings:
        # Under real OIDC the two-person rule is not optional: relaxing it there
        # would let one authenticated admin send to real mailboxes unreviewed.
        if not self.dev_auth_mode and self.approval_policy is ApprovalPolicy.SINGLE_ADMIN:
            raise ValueError(
                "OPERATOR_API_APPROVAL_POLICY=single-admin is not permitted when OIDC is enabled; "
                "use 'enforce' (two-person approval) outside the dev-auth stack"
            )
        return self

    def require_secret_key(self) -> bytes:
        if not self.audit_hmac_key:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY is required")
        try:
            key = bytes.fromhex(self.audit_hmac_key)
        except ValueError as exc:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY must be a hex string") from exc
        if len(key) != 32:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_cipher_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK is required")
        try:
            kek = bytes.fromhex(self.ciphertext_kek)
        except ValueError as exc:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK must be a hex string") from exc
        if len(kek) != 32:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK must be a 256-bit hex key (64 hex chars)")
        return kek

    def require_console_jwt_secret(self) -> bytes:
        if not self.console_jwt_secret:
            raise RuntimeError("OPERATOR_API_CONSOLE_JWT_SECRET is required")
        secret = self.console_jwt_secret.encode()
        if len(secret) < 32:
            raise RuntimeError("OPERATOR_API_CONSOLE_JWT_SECRET must be at least 32 bytes")
        return secret

    def require_recipient_hash_salt(self) -> bytes:
        if not self.recipient_hash_salt:
            raise RuntimeError("OPERATOR_API_RECIPIENT_HASH_SALT is required")
        try:
            salt = bytes.fromhex(self.recipient_hash_salt)
        except ValueError as exc:
            raise RuntimeError("OPERATOR_API_RECIPIENT_HASH_SALT must be a hex string") from exc
        if len(salt) < 16:
            raise RuntimeError("OPERATOR_API_RECIPIENT_HASH_SALT must be at least 16 bytes")
        return salt
