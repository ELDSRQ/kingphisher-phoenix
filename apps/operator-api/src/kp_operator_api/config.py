"""Operator API configuration.

All values come from the environment. Secrets are never committed; the local
defaults in .env.example are for the disposable dev stack only.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class OperatorApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPERATOR_API_", env_file=".env", extra="ignore")

    app_name: str = "kp-operator-api"
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
    log_level: str = "info"
    rate_limit_user_per_min: int = 120
    rate_limit_ip_per_min: int = 600
    max_body_bytes: int = 1_000_000
    redis_url: str = "redis://localhost:6379/0"
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://localhost:3000/training/awareness"
    training_domains: str = "example.com,training.local"
    env_file: str = ".env"
    console_static_dir: str = "apps/operator-ui/src/console"

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
