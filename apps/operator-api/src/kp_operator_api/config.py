"""Operator API configuration.

All values come from the environment. Secrets are never committed; the local
defaults in .env.example are for the disposable dev stack only.
"""

from __future__ import annotations

import re
import uuid
from typing import Literal

from kp_database.awareness_ledger import (
    LOCAL_AWARENESS_PSEUDONYM_KEY,
    LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION,
)
from kp_domain_models.policy import ApprovalPolicy, parse_domain_allowlist
from kp_telemetry.settings import local_dotenv_file
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ACS_TOPIC = re.compile(
    r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/]+/providers/"
    r"Microsoft\.Communication/CommunicationServices/[^/]+\Z",
    re.IGNORECASE,
)
_CIPHERTEXT_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_MAX_CIPHERTEXT_PRIOR_KEYS = 4


class OperatorApiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OPERATOR_API_",
        env_file=local_dotenv_file(),
        # Empty env/.env values ("") are treated as unset so optional fields use
        # their defaults; a fresh .env from .env.example must work unmodified.
        env_ignore_empty=True,
        extra="ignore",
        populate_by_name=True,
        hide_input_in_errors=True,
    )

    app_name: str = "kp-operator-api"
    deployment_mode: Literal["single_tenant"] = "single_tenant"
    host: str = "127.0.0.1"
    port: int = 8000
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    ciphertext_key_id: str = "primary"
    ciphertext_prior_keys: str = Field(default="", max_length=512)
    console_jwt_secret: str = ""
    recipient_hash_salt: str = ""
    #: Stable key and governed version for the PII-free awareness ledger
    #: (RET-005). Must match the retention worker's key so named drill-down
    #: resolves the pseudonyms the worker projected; like the RoE key, a shared
    #: unprefixed alias lets one managed value serve both API and workers.
    awareness_pseudonym_key: str = Field(
        default="",
        max_length=128,
        repr=False,
        validation_alias=AliasChoices(
            "OPERATOR_API_AWARENESS_PSEUDONYM_KEY",
            "KP_WORKER_AWARENESS_PSEUDONYM_KEY",
        ),
    )
    awareness_pseudonym_key_version: str = Field(
        default="",
        max_length=32,
        validation_alias=AliasChoices(
            "OPERATOR_API_AWARENESS_PSEUDONYM_KEY_VERSION",
            "KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION",
        ),
    )
    tracking_token_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices("OPERATOR_API_TRACKING_TOKEN_HMAC_KEY", "TRACKING_TOKEN_HMAC_KEY"),
    )
    training_token_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices("OPERATOR_API_TRAINING_TOKEN_HMAC_KEY", "TRAINING_TOKEN_HMAC_KEY"),
    )
    # Event Grid uses Entra authentication at the public webhook. This
    # independent 256-bit key binds the already-authenticated event to the
    # private Redis job consumed by the delivery worker; it is never sent by
    # Event Grid or returned through an API.
    acs_receipt_signing_key: str = ""
    event_grid_tenant_id: str = ""
    event_grid_audience: str = ""
    event_grid_subscription_name: str = ""
    event_grid_topic: str = ""
    event_grid_publisher_app_id: str = "4962773b-9cdb-44cf-a8bf-237846a00ab7"
    event_grid_max_body_bytes: int = Field(default=262_144, ge=1024, le=1_000_000)
    event_grid_max_events: int = Field(default=64, ge=1, le=64)
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
    # AUD-003 witness-freshness gate. Default ON, but fail-OPEN on an absent
    # heartbeat or a Redis blip (see _audit_mutation_state_is_healthy), so it is
    # safe on a fresh/just-restarted local stack and on Azure. The interval must
    # match the anchor worker's; the shared unprefixed alias lets one value drive
    # both the API and the workers (as with the T-06 policy vars).
    audit_anchor_gate_enabled: bool = True
    audit_anchor_interval_seconds: int = Field(
        default=3600,
        ge=60,
        le=86400,
        validation_alias=AliasChoices("OPERATOR_API_AUDIT_ANCHOR_INTERVAL_SECONDS", "AUDIT_ANCHOR_INTERVAL_SECONDS"),
    )
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://127.0.0.1:8001/v1/training/awareness"
    training_domains: str = "example.com,127.0.0.1"
    env_file: str = ".env"
    console_static_dir: str = "apps/operator-ui/src/console"

    # --- send-safety policy (T-06) ---
    # Both accept a shared, unprefixed env var so an operator sets one value
    # for the API and the workers instead of two that can silently diverge.
    #
    # PLT-002 SAFETY CHANGE: the default is ENFORCE (two-person), not
    # SINGLE_ADMIN. SINGLE_ADMIN is a disposable-dev relaxation and is now
    # refused unless the operator explicitly marks the stack with KP_DEV_STACK=1
    # AND runs dev-auth (see validate_approval_policy). This stops one env flip
    # from collapsing separation-of-duties.
    approval_policy: ApprovalPolicy = Field(
        default=ApprovalPolicy.ENFORCE,
        validation_alias=AliasChoices("OPERATOR_API_APPROVAL_POLICY", "OPERATOR_APPROVAL_POLICY"),
    )
    #: Explicit "this is a throwaway local dev stack" marker (shared, unprefixed
    #: KP_DEV_STACK). Required to unlock the unsafe dev relaxations — SINGLE_ADMIN
    #: approvals and empty-allowlist allow-all — so those can never be reached by
    #: default or by a single accidental env flip. Off in every hardened/managed
    #: deployment.
    dev_stack: bool = Field(
        default=False,
        validation_alias=AliasChoices("KP_DEV_STACK", "OPERATOR_API_DEV_STACK"),
    )
    #: Which receipts (delivery-event ingress) backend this deployment uses.
    #: PLT-002 seam: the ACS/Event-Grid ingress hardening below keys on THIS,
    #: not on "managed", so identity/hosting posture is decoupled from the mail
    #: provider. Defaults to "acs_eventgrid" to preserve prior managed behavior.
    #: A hardened non-ACS deployment sets "none" and is not asked for Event Grid.
    receipts_provider: Literal["none", "acs_eventgrid"] = "acs_eventgrid"
    allowed_recipient_domains: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPERATOR_API_ALLOWED_RECIPIENT_DOMAINS",
            "KP_ALLOWED_RECIPIENT_DOMAINS",
        ),
    )
    alert_webhook_domains: str = Field(
        default="",
        validation_alias=AliasChoices(
            "OPERATOR_API_ALERT_WEBHOOK_DOMAINS",
            "KP_WORKER_ALERT_WEBHOOK_DOMAINS",
        ),
    )
    #: Shared key that signs Rules-of-Engagement. RoE creation and the
    #: delivery gate use the same value so a campaign scheduled under a signed
    #: RoE is verifiable by the workers that deliver it.
    roe_signing_key: str = Field(
        default="",
        validation_alias=AliasChoices("OPERATOR_API_ROE_SIGNING_KEY", "KP_ROE_SIGNING_KEY"),
    )
    #: Key that mints the DNS-challenge tokens used to prove domain control.
    #: Distinct from the RoE key so a leaked challenge token can never be used
    #: to forge an authorization.
    domain_verification_key: str = Field(
        default="", validation_alias=AliasChoices("OPERATOR_API_DOMAIN_VERIFY_KEY", "KP_DOMAIN_VERIFY_KEY")
    )
    #: Recipients per delivery message; bounds the 1MiB queue payload cap.
    delivery_batch_size: int = Field(default=200, ge=1, le=2000)

    #: Where runtime configuration actually lives.
    #:
    #: "env_file"  - the disposable local stack: the console may edit .env and
    #:               supervise worker processes.
    #: "managed"   - Azure Container Apps: configuration comes from Terraform
    #:               and Key Vault, the filesystem is ephemeral, and there is no
    #:               local supervisor. Console endpoints that would write .env or
    #:               signal processes refuse instead of silently doing nothing.
    config_store: Literal["env_file", "managed"] = "env_file"

    @property
    def config_is_managed(self) -> bool:
        return self.config_store == "managed"

    @property
    def dev_auth_mode(self) -> bool:
        """True when running the offline dev-auth stack rather than real OIDC."""
        return self.oidc_mode == "dev"

    def recipient_domain_allowlist(self) -> frozenset[str]:
        return parse_domain_allowlist(self.allowed_recipient_domains)

    def alert_webhook_domain_allowlist(self) -> frozenset[str]:
        """Return the shared operator/worker outbound-alert destination policy."""

        return parse_domain_allowlist(self.alert_webhook_domains)

    @property
    def dev_relaxations_allowed(self) -> bool:
        """True only for an explicitly-marked disposable dev-auth stack.

        Gate for the unsafe relaxations (SINGLE_ADMIN approvals; empty-allowlist
        allow-all). Requires BOTH dev-auth AND the explicit KP_DEV_STACK marker,
        so neither the default nor a single accidental env flip can reach them.
        """
        return self.dev_auth_mode and self.dev_stack

    @model_validator(mode="after")
    def validate_approval_policy(self) -> OperatorApiSettings:
        # SINGLE_ADMIN is a disposable-dev relaxation. It is refused unless the
        # stack is explicitly marked dev (KP_DEV_STACK=1) AND runs dev-auth. The
        # message keeps the historical "is not permitted" prefix so existing
        # operators/tests still recognize it.
        if self.approval_policy is ApprovalPolicy.SINGLE_ADMIN and not self.dev_relaxations_allowed:
            raise ValueError(
                "OPERATOR_API_APPROVAL_POLICY=single-admin is not permitted here; it requires the dev-auth "
                "stack explicitly marked with KP_DEV_STACK=1. Use 'enforce' (two-person approval) otherwise"
            )
        # PLT-002: a managed (hardened) posture must run real OIDC. Previously
        # managed+dev-auth silently skipped every managed check below; now it is
        # refused outright. Only managed+dev is refused — env_file+dev (the
        # disposable local stack, incl. .105) is unaffected.
        if self.config_is_managed and self.dev_auth_mode:
            raise ValueError(
                "OPERATOR_API_CONFIG_STORE=managed requires OPERATOR_API_OIDC_MODE=oidc; "
                "dev-auth is refused under the managed posture"
            )
        # PLT-002 seam: ACS/Event-Grid receipt-ingress hardening keys on the
        # receipts provider, not on "managed" alone, so a hardened non-ACS
        # deployment (receipts_provider=none) is not forced to configure Event
        # Grid. Managed here always implies OIDC (guarded above).
        if self.config_is_managed and self.receipts_provider == "acs_eventgrid":
            try:
                self.require_acs_receipt_signing_key()
                uuid.UUID(self.event_grid_tenant_id)
                uuid.UUID(self.event_grid_audience)
                uuid.UUID(self.event_grid_publisher_app_id)
            except (RuntimeError, ValueError):
                raise ValueError(
                    "managed ACS receipt ingress is not securely configured; verify the signing key and "
                    "Event Grid identifiers"
                ) from None
            if not self.event_grid_subscription_name.strip() or len(self.event_grid_subscription_name) > 128:
                raise ValueError("managed ACS receipt ingress requires a bounded Event Grid subscription name")
            if _ACS_TOPIC.fullmatch(self.event_grid_topic.strip()) is None:
                raise ValueError("managed ACS receipt ingress requires the exact ACS Communication Service topic")
        return self

    def require_acs_receipt_signing_key(self) -> bytes:
        value = self.acs_receipt_signing_key
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise RuntimeError("OPERATOR_API_ACS_RECEIPT_SIGNING_KEY must be 64 lowercase hexadecimal characters")
        return bytes.fromhex(value)

    def require_secret_key(self) -> bytes:
        if not self.audit_hmac_key:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY is required")
        try:
            key = bytes.fromhex(self.audit_hmac_key)
        except ValueError:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY must be a hex string") from None
        if len(key) != 32:
            raise RuntimeError("OPERATOR_API_AUDIT_HMAC_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_roe_signing_key(self) -> bytes:
        if not self.roe_signing_key:
            raise RuntimeError("KP_ROE_SIGNING_KEY is required to sign Rules-of-Engagement")
        try:
            key = bytes.fromhex(self.roe_signing_key)
        except ValueError:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a hex string") from None
        if len(key) != 32:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_domain_verification_key(self) -> bytes:
        if not self.domain_verification_key:
            raise RuntimeError("KP_DOMAIN_VERIFY_KEY is required to run DNS-challenge verification")
        try:
            key = bytes.fromhex(self.domain_verification_key)
        except ValueError:
            raise RuntimeError("KP_DOMAIN_VERIFY_KEY must be a hex string") from None
        if len(key) != 32:
            raise RuntimeError("KP_DOMAIN_VERIFY_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_cipher_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK is required")
        if re.fullmatch(r"[0-9a-fA-F]{64}", self.ciphertext_kek) is None:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEK must be a 256-bit hex key (64 hex chars)") from None
        return bytes.fromhex(self.ciphertext_kek)

    def require_cipher_keyring(self) -> tuple[str, bytes, dict[str, bytes]]:
        """Return the active write key and bounded prior decrypt-only keys."""
        active_key = self.require_cipher_kek()
        active_key_id = self.ciphertext_key_id.strip()
        if _CIPHERTEXT_KEY_ID.fullmatch(active_key_id) is None:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_KEY_ID must contain 1-32 ASCII letters, digits, '_' or '-'")

        raw_entries = self.ciphertext_prior_keys.split(",") if self.ciphertext_prior_keys.strip() else []
        if len(raw_entries) > _MAX_CIPHERTEXT_PRIOR_KEYS:
            raise RuntimeError("OPERATOR_API_CIPHERTEXT_PRIOR_KEYS supports at most four entries")
        prior_keys: dict[str, bytes] = {}
        for entry in raw_entries:
            key_id, separator, key_hex = entry.strip().partition("=")
            if not separator or _CIPHERTEXT_KEY_ID.fullmatch(key_id) is None:
                raise RuntimeError("OPERATOR_API_CIPHERTEXT_PRIOR_KEYS must use comma-separated key-id=64-hex entries")
            if key_id == active_key_id or key_id in prior_keys:
                raise RuntimeError("OPERATOR_API_CIPHERTEXT_PRIOR_KEYS key identifiers must be unique")
            if re.fullmatch(r"[0-9a-fA-F]{64}", key_hex) is None:
                raise RuntimeError(
                    "OPERATOR_API_CIPHERTEXT_PRIOR_KEYS key material must be 256-bit hexadecimal"
                ) from None
            key = bytes.fromhex(key_hex)
            if key == active_key or key in prior_keys.values():
                raise RuntimeError("OPERATOR_API_CIPHERTEXT_PRIOR_KEYS must not reuse key material")
            prior_keys[key_id] = key
        return active_key_id, active_key, prior_keys

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
        except ValueError:
            raise RuntimeError("OPERATOR_API_RECIPIENT_HASH_SALT must be a hex string") from None
        if len(salt) < 16:
            raise RuntimeError("OPERATOR_API_RECIPIENT_HASH_SALT must be at least 16 bytes")
        return salt

    def require_awareness_pseudonym_config(self) -> tuple[bytes, str]:
        """Return the stable ledger key and governed version for named drill-down.

        Must match the retention worker's key so per-recipient history resolves
        the pseudonyms the worker projected. Development has one deterministic
        synthetic value (shared with the worker) so disposable local databases
        remain reproducible; managed mode never falls back to it.
        """

        key_hex = self.awareness_pseudonym_key
        version = self.awareness_pseudonym_key_version
        if not self.config_is_managed:
            key_hex = key_hex or LOCAL_AWARENESS_PSEUDONYM_KEY
            version = version or LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION
        if re.fullmatch(r"[0-9a-f]{64,128}", key_hex) is None or len(key_hex) % 2 != 0:
            raise RuntimeError(
                "OPERATOR_API_AWARENESS_PSEUDONYM_KEY must be a 32-64-byte lowercase hexadecimal key"
            ) from None
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z", version) is None:
            raise RuntimeError(
                "OPERATOR_API_AWARENESS_PSEUDONYM_KEY_VERSION must be a governed 1-32 character identifier"
            ) from None
        return bytes.fromhex(key_hex), version

    def require_tracking_token_hmac_key(self) -> bytes:
        if not self.tracking_token_hmac_key:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY is required to issue tracking bearers")
        try:
            key = bytes.fromhex(self.tracking_token_hmac_key)
        except ValueError:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key")
        return key

    def require_training_token_hmac_key(self) -> bytes:
        if not self.training_token_hmac_key:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY is required to issue training bearers")
        try:
            key = bytes.fromhex(self.training_token_hmac_key)
        except ValueError:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key")
        return key
