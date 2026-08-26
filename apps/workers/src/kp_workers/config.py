from typing import Literal
from urllib.parse import urlparse

from kp_domain_models.policy import ApprovalPolicy, parse_domain_allowlist
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _validate_provider_url(name: str, value: str | None) -> None:
    if not value:
        return
    parsed = urlparse(value)
    local_hosts = {"localhost", "127.0.0.1", "::1", "mock-graph", "mock-ai", "mailpit"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (parsed.scheme != "https" and parsed.hostname.lower() not in local_hosts)
    ):
        raise ValueError(f"{name} must be HTTPS (HTTP is allowed only for local development)")


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KP_WORKER_", env_file=".env", extra="ignore", populate_by_name=True)

    worker_name: str = "worker"
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    redis_url: str = "redis://localhost:6379/0"
    queue_prefix: str = "kp:queue:"
    poll_seconds: int = 5
    max_retries: int = 3
    visibility_seconds: int = 60
    recovery_every_polls: int = 12
    retention_interval_seconds: int = 86400
    log_level: str = "info"
    mock_graph_url: str = "http://localhost:8181"
    mock_ai_url: str = "http://localhost:8282"
    mailpit_smtp: str = "localhost:1025"
    mailpit_api_url: str = "http://localhost:8025"
    graph_base_url: str | None = None
    graph_bearer_token: str | None = None
    graph_api_key: str | None = None
    graph_max_users: int = Field(default=1000, ge=1, le=10000)
    graph_max_pages: int = Field(default=20, ge=1, le=100)
    recipient_hash_salt: str = ""
    ai_base_url: str | None = None
    ai_bearer_token: str | None = None
    ai_api_key: str | None = None
    smtp_address: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool | None = None
    smtp_ssl: bool = False
    smtp_sender: str | None = None
    email_provider: Literal["smtp", "azure_communication_services"] = "smtp"
    acs_email_endpoint: str | None = None
    acs_email_connection_string: str | None = None
    reported_mailbox_url: str | None = None
    reported_mailbox_bearer_token: str | None = None
    reported_mailbox_basic_username: str | None = None
    reported_mailbox_basic_password: str | None = None
    provider_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    mailbox_poll_limit: int = 50
    reminder_after_hours: int = 72
    reminder_batch_size: int = 100
    reminder_sender: str = "security-awareness@example.com"
    alert_webhook_domains: str = ""
    tracking_base_url: str = "http://localhost:8001"
    training_base_url: str = "http://127.0.0.1:8001/v1/training/awareness"
    training_domains: str = "example.com,127.0.0.1"

    # --- send-safety policy (T-06); mirrors the operator API ---
    approval_policy: ApprovalPolicy = Field(
        default=ApprovalPolicy.SINGLE_ADMIN,
        validation_alias=AliasChoices("KP_WORKER_APPROVAL_POLICY", "OPERATOR_APPROVAL_POLICY"),
    )
    allowed_recipient_domains: str = Field(
        default="",
        validation_alias=AliasChoices("KP_WORKER_ALLOWED_RECIPIENT_DOMAINS", "KP_ALLOWED_RECIPIENT_DOMAINS"),
    )
    #: Shared key that signs Rules-of-Engagement. Delivery verifies the
    #: campaign's RoE signature before honoring it; without the key (or a
    #: valid signature) delivery fails closed.
    roe_signing_key: str = Field(
        default="",
        validation_alias=AliasChoices("KP_WORKER_ROE_SIGNING_KEY", "KP_ROE_SIGNING_KEY"),
    )
    #: Pool of domains this deployment is authenticated to send *as* (the
    #: registered lookalike/sending domains). A campaign's requested sender
    #: mailbox is honored only when it sits in the pool; otherwise the
    #: envelope falls back to the configured default sender, because mail
    #: from an unauthenticated domain does not deliver.
    sending_domains: str = Field(
        default="",
        validation_alias=AliasChoices("KP_WORKER_SENDING_DOMAINS", "KP_SENDING_DOMAINS"),
    )
    #: Brands/domains the operator's own lures are allowed to imitate (their
    #: sending domains and internal brand). Fed to the neutralizer so a
    #: legitimate lookalike-domain template is not flagged as malicious.
    brand_allowlist: str = Field(
        default="",
        validation_alias=AliasChoices("KP_WORKER_BRAND_ALLOWLIST", "KP_BRAND_ALLOWLIST"),
    )
    #: QUEUED assignments older than this on a finished campaign are reconciled
    #: to FAILED. Never auto-resent — a human decides whether to re-run.
    queued_stale_hours: int = Field(default=24, ge=1, le=720)
    #: Consecutive poll failures before a source is disabled (circuit breaker).
    source_failure_threshold: int = Field(default=10, ge=1, le=1000)
    #: Recipients per delivery message. Bounds queue payload size (1MiB cap) and
    #: gives the sender a natural batch for one reused SMTP/ACS connection.
    delivery_batch_size: int = Field(default=200, ge=1, le=2000)

    @model_validator(mode="after")
    def validate_provider_credentials(self) -> "WorkerSettings":
        if self.smtp_ssl and self.smtp_starttls:
            raise ValueError("SMTP SSL and STARTTLS cannot both be enabled")
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError("SMTP username and password must be configured together")
        if self.email_provider == "azure_communication_services" and not self.acs_email_endpoint:
            raise ValueError("ACS email endpoint is required for the Azure Communication Services provider")
        _validate_provider_url("ACS email endpoint", self.acs_email_endpoint)
        basic_values = (self.reported_mailbox_basic_username, self.reported_mailbox_basic_password)
        if any(basic_values) and not all(basic_values):
            raise ValueError("reported mailbox basic username and password must be configured together")
        if self.reported_mailbox_bearer_token and all(basic_values):
            raise ValueError("reported mailbox bearer and basic authentication cannot both be configured")
        _validate_provider_url("Graph base URL", self.graph_base_url)
        _validate_provider_url("AI base URL", self.ai_base_url)
        _validate_provider_url("reported mailbox URL", self.reported_mailbox_url)
        return self

    def recipient_domain_allowlist(self) -> frozenset[str]:
        return parse_domain_allowlist(self.allowed_recipient_domains)

    def sending_domain_pool(self) -> frozenset[str]:
        return parse_domain_allowlist(self.sending_domains)

    def brand_allowlist_set(self) -> set[str]:
        return {d.strip().lower() for d in self.brand_allowlist.split(",") if d.strip()}

    @property
    def effective_smtp_address(self) -> str:
        return self.smtp_address or self.mailpit_smtp

    @property
    def effective_smtp_sender(self) -> str:
        return self.smtp_sender or self.reminder_sender

    @property
    def effective_smtp_starttls(self) -> bool:
        if self.smtp_starttls is not None:
            return self.smtp_starttls
        host = self.effective_smtp_address.rpartition(":")[0].strip("[]").lower()
        return host not in {"localhost", "127.0.0.1", "::1", "mailpit"} and not self.smtp_ssl

    @property
    def effective_reported_mailbox_url(self) -> str:
        return self.reported_mailbox_url or self.mailpit_api_url

    @property
    def effective_ai_base_url(self) -> str:
        return self.ai_base_url or self.mock_ai_url

    @property
    def effective_graph_base_url(self) -> str:
        return self.graph_base_url or self.mock_graph_url

    def require_hmac(self) -> bytes:
        if not self.audit_hmac_key:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY is required")
        try:
            key = bytes.fromhex(self.audit_hmac_key)
        except ValueError as exc:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY must be a hex string") from exc
        if len(key) != 32:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_roe_signing_key(self) -> bytes:
        if not self.roe_signing_key:
            raise RuntimeError("KP_ROE_SIGNING_KEY is required to verify Rules-of-Engagement")
        try:
            key = bytes.fromhex(self.roe_signing_key)
        except ValueError as exc:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a hex string") from exc
        if len(key) != 32:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK is required")
        try:
            kek = bytes.fromhex(self.ciphertext_kek)
        except ValueError as exc:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK must be a hex string") from exc
        if len(kek) != 32:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK must be a 256-bit hex key (64 hex chars)")
        return kek

    def require_recipient_hash_salt(self) -> bytes:
        if not self.recipient_hash_salt:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT is required")
        try:
            salt = bytes.fromhex(self.recipient_hash_salt)
        except ValueError as exc:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT must be a hex string") from exc
        if len(salt) < 16:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT must be at least 16 bytes")
        return salt

    def training_domain_set(self) -> set[str]:
        return {d.strip().lower() for d in self.training_domains.split(",") if d.strip()}

    def alert_webhook_domain_set(self) -> set[str]:
        return {d.strip().lower() for d in self.alert_webhook_domains.split(",") if d.strip()}
