"""Operator API configuration.

All values come from the environment. Secrets are never committed; the local
defaults in .env.example are for the disposable dev stack only.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class OperatorApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPERATOR_API_", env_file=".env", extra="ignore")

    app_name: str = "kp-operator-api"
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    oidc_issuer: str = "http://localhost:8443/realms/kingphisher"
    oidc_audience: str = "kp-operator-api"
    log_level: str = "info"
    rate_limit_per_minute: int = 120
    redis_url: str = "redis://localhost:6379/0"
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://localhost:3000/training/awareness"
    training_domains: str = "example.com,training.local"
    env_file: str = ".env"
    console_static_dir: str = "apps/operator-ui/src/console"

    def require_secret_key(self) -> bytes:
        if not self.audit_hmac_key:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY is required")
        return self.audit_hmac_key.encode()

    def require_cipher_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK is required")
        return self.ciphertext_kek.encode()
