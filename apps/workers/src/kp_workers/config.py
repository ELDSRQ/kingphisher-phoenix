import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal
from urllib.parse import urlparse

from kp_database.awareness_ledger import (
    LOCAL_AWARENESS_PSEUDONYM_KEY,
    LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION,
)
from kp_domain_models.policy import ApprovalPolicy, parse_domain_allowlist
from kp_telemetry.settings import local_dotenv_file
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_LOCAL_PROVIDER_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "mock-graph", "mock-ai", "mailpit"})
_MANAGED_RUNTIME_MODES = frozenset({"managed", "production"})
_MICROSOFT_GRAPH_HOST = "graph.microsoft.com"
# Azure Communication Services data-plane endpoints carry a data-location label
# when the resource has a data_location (e.g. <name>.unitedstates.communication
# .azure.com); accept that optional middle label as well as the plain
# <name>.communication.azure.com form. The whole domain is Azure-owned and the
# \Z anchor still rejects suffix tricks (…communication.azure.com.attacker.tld)
# and deeper (3+ label) nesting.
_ACS_ENDPOINT_HOST = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?"
    r"\.communication\.azure\.com\Z",
    re.IGNORECASE,
)
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_MAILBOX = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_ACS_LOCAL_PART = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}\Z")
_ACS_DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_CIPHERTEXT_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_AWARENESS_PSEUDONYM_KEY_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")
_MAX_CIPHERTEXT_PRIOR_KEYS = 4


class EmailProviderKind(StrEnum):
    """Resolved email transport kind.

    Values are the canonical provider strings persisted on the delivery gate
    and carried in the config, so ``.value`` stays wire-compatible with
    ``email_provider``. Code must branch on this enum, not on string
    literals, so a new provider or a typo cannot silently fork a consumer
    (the F-1 lesson).
    """

    SMTP = "smtp"
    AZURE_COMMUNICATION_SERVICES = "azure_communication_services"

    @property
    def is_acs(self) -> bool:
        return self is EmailProviderKind.AZURE_COMMUNICATION_SERVICES

    @property
    def metrics_name(self) -> str:
        """Short provider label used in metric labels and operator logs."""

        return "acs" if self.is_acs else "smtp"


def _is_local_provider_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.rstrip(".").lower()
    return normalized in _LOCAL_PROVIDER_HOSTS or normalized.endswith(".localhost")


def _validate_provider_url(name: str, value: str | None) -> None:
    if not value:
        return
    error = f"{name} must be HTTPS without credentials, query parameters, or fragments"
    error += " (HTTP is allowed only for local development)"
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        # Accessing ``port`` performs urllib's delayed validation.  Do that
        # here so a malformed value cannot later escape in an exception.
        _ = parsed.port
    except ValueError:
        raise ValueError(error) from None
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and not _is_local_provider_host(hostname))
    ):
        raise ValueError(error)


def _require_managed_provider_url(name: str, value: str | None) -> None:
    if not value:
        raise ValueError(f"{name} is required in managed and production runtime modes")
    _validate_provider_url(name, value)
    parsed = urlparse(value)
    if parsed.scheme != "https" or _is_local_provider_host(parsed.hostname):
        raise ValueError(f"{name} must use a non-local HTTPS endpoint in managed and production runtime modes")


def _require_acs_production_endpoint(value: str | None) -> None:
    """Require the native ACS data-plane endpoint before managed delivery."""

    name = "ACS email endpoint"
    if not value:
        raise ValueError(f"{name} is required in managed and production runtime modes")
    _validate_provider_url(name, value)
    error = f"{name} must use an approved HTTPS *.communication.azure.com endpoint on port 443"
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError:
        raise ValueError(error) from None
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or port not in {None, 443}
        or parsed.path not in {"", "/"}
        or _ACS_ENDPOINT_HOST.fullmatch(hostname) is None
    ):
        raise ValueError(error)


def _require_uuid(name: str, value: str | None) -> None:
    if not value or _UUID.fullmatch(value.strip()) is None:
        raise ValueError(f"{name} must be a complete UUID")


def _provider_hostname(value: str | None) -> str | None:
    if not value:
        return None
    try:
        hostname = urlparse(value).hostname
    except ValueError:
        return None
    return hostname.lower() if hostname else None


def _smtp_hostname(address: str) -> str | None:
    host, separator, port = address.rpartition(":")
    if not separator or not host or not port.isdigit():
        return None
    return host.strip("[]")


class WorkerSettings(BaseSettings):
    # Configuration validation commonly runs during process startup, where an
    # uncaught ValidationError may be rendered by the process manager.  Keep
    # Pydantic from embedding the supplied settings mapping (and therefore
    # credentials) in that diagnostic.
    model_config = SettingsConfigDict(
        env_prefix="KP_WORKER_",
        env_file=local_dotenv_file(),
        extra="ignore",
        populate_by_name=True,
        hide_input_in_errors=True,
    )

    worker_name: str = "worker"
    runtime_mode: Literal["development", "managed", "production"] = Field(
        default="development",
        validation_alias=AliasChoices("KP_WORKER_RUNTIME_MODE", "KP_WORKER_DEPLOYMENT_MODE"),
    )
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    audit_database_url: str = "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
    audit_hmac_key: str = ""
    ciphertext_kek: str = ""
    ciphertext_key_id: str = "primary"
    ciphertext_prior_keys: str = Field(default="", max_length=512)
    awareness_pseudonym_key: str = Field(default="", max_length=128, repr=False)
    awareness_pseudonym_key_version: str = Field(default="", max_length=32)
    redis_url: str = "redis://localhost:6379/0"
    poll_seconds: int = 5
    max_retries: int = 3
    visibility_seconds: int = 60
    recovery_every_polls: int = 12
    retention_interval_seconds: int = 86400
    audit_anchor_interval_seconds: int = Field(default=3600, ge=60, le=86400)
    audit_anchor_container_url: str | None = None
    audit_anchor_client_id: str | None = None
    log_level: str = "info"
    mock_graph_url: str = "http://localhost:8181"
    mock_ai_url: str = "http://localhost:8282"
    mailpit_smtp: str = "localhost:1025"
    mailpit_api_url: str = "http://localhost:8025"
    graph_base_url: str | None = None
    graph_bearer_token: str | None = None
    graph_api_key: str | None = None
    graph_client_id: str | None = None
    graph_group_ids: str = ""
    microsoft_tenant_id: str | None = None
    graph_max_users: int = Field(default=1000, ge=1, le=10000)
    graph_max_pages: int = Field(default=20, ge=1, le=100)
    recipient_hash_salt: str = ""
    ai_base_url: str | None = None
    ai_bearer_token: str | None = None
    ai_api_key: str | None = None
    #: Exact identity of the model the bake-off selected and this worker is
    #: permitted to call. When set, every generation response's self-reported
    #: ``model_id`` must match this constant-time identity or the call fails
    #: closed: a swapped model cannot silently change what the human reviews.
    ai_model_id: str | None = Field(default=None, min_length=1, max_length=128)
    smtp_address: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool | None = None
    smtp_ssl: bool = False
    smtp_sender: str | None = None
    email_provider: EmailProviderKind = EmailProviderKind.SMTP
    acs_email_endpoint: str | None = None
    acs_email_connection_string: str | None = None
    acs_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("KP_WORKER_ACS_CLIENT_ID", "ACS_CLIENT_ID"),
    )
    acs_sending_domain: str | None = None
    acs_sender_local_part: str | None = None
    acs_sender_display_name: str = ""
    acs_domain_verification_status: str = "unverified"
    acs_spf_verification_status: str = "unverified"
    acs_dkim_verification_status: str = "unverified"
    acs_dkim2_verification_status: str = "unverified"
    acs_sender_username_status: str = "unverified"
    acs_readiness_checked_at: str | None = None
    acs_readiness_max_age_hours: int = Field(default=24, ge=1, le=168)
    acs_daily_message_limit: int | None = Field(default=None, ge=1, le=1_000_000)
    acs_messages_per_minute: int | None = Field(default=None, ge=1, le=10_000)
    acs_ramp_batch_size: int | None = Field(default=None, ge=1, le=2_000)
    acs_ramp_interval_seconds: int | None = Field(default=None, ge=1, le=3_600)
    acs_receipt_signing_key: str = Field(default="", min_length=0, max_length=128)
    reported_mailbox_url: str | None = None
    reported_mailbox_provider: Literal["mailpit", "microsoft365"] = "mailpit"
    reported_mailbox_client_id: str | None = None
    reported_mailbox_id: str | None = None
    reported_mailbox_folder_id: str = "inbox"
    reported_mailbox_bearer_token: str | None = None
    reported_mailbox_basic_username: str | None = None
    reported_mailbox_basic_password: str | None = None
    provider_timeout_seconds: float = Field(default=10.0, ge=0.1, le=60.0)
    mailbox_poll_limit: int = 50
    reminder_batch_size: int = 100
    reminder_sender: str = "security-awareness@example.com"
    training_token_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices("KP_WORKER_TRAINING_TOKEN_HMAC_KEY", "TRAINING_TOKEN_HMAC_KEY"),
    )
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
        if (
            self.worker_name in {"delivery", "reminder"}
            and self.email_provider_kind.is_acs
            and not self.acs_email_endpoint
        ):
            raise ValueError("ACS email endpoint is required for the Azure Communication Services provider")
        _validate_provider_url("ACS email endpoint", self.acs_email_endpoint)
        basic_values = (self.reported_mailbox_basic_username, self.reported_mailbox_basic_password)
        if any(basic_values) and not all(basic_values):
            raise ValueError("reported mailbox basic username and password must be configured together")
        if self.reported_mailbox_bearer_token and all(basic_values):
            raise ValueError("reported mailbox bearer and basic authentication cannot both be configured")
        if (
            self.graph_client_id
            and self.reported_mailbox_client_id
            and self.graph_client_id.strip().lower() == self.reported_mailbox_client_id.strip().lower()
        ):
            raise ValueError("directory and reported mailbox must use distinct managed identity client IDs")
        _validate_provider_url("mock Graph URL", self.mock_graph_url)
        _validate_provider_url("mock AI URL", self.mock_ai_url)
        _validate_provider_url("Mailpit API URL", self.mailpit_api_url)
        _validate_provider_url("Graph base URL", self.graph_base_url)
        _validate_provider_url("AI base URL", self.ai_base_url)
        _validate_provider_url("reported mailbox URL", self.reported_mailbox_url)
        if self.ai_model_id and ("\x00" in self.ai_model_id or "\r" in self.ai_model_id or "\n" in self.ai_model_id):
            raise ValueError("AI model ID must be a single line without control characters")
        _validate_provider_url("tracking base URL", self.tracking_base_url)
        _validate_provider_url("training base URL", self.training_base_url)
        if self.audit_anchor_container_url:
            self._validate_audit_anchor_container_url()
        if self.runtime_mode in _MANAGED_RUNTIME_MODES:
            self._validate_managed_role_providers()
        return self

    def _validate_managed_role_providers(self) -> None:
        if self.worker_name == "audit-anchor":
            self.require_audit_anchor_configured()
        elif self.worker_name == "directory":
            _require_managed_provider_url("Graph base URL", self.graph_base_url)
            _require_uuid("Microsoft tenant ID", self.microsoft_tenant_id)
            _require_uuid("Graph directory client ID", self.graph_client_id)
            if not self.graph_group_id_set():
                raise ValueError("Graph directory group IDs are required for selected-group synchronization")
            if _provider_hostname(self.graph_base_url) == _MICROSOFT_GRAPH_HOST:
                if self.graph_bearer_token or self.graph_api_key:
                    raise ValueError("native Microsoft Graph must use its dedicated managed identity")
            elif not self.graph_api_key:
                raise ValueError("custom Graph gateways require an explicit API key")
            if self.graph_bearer_token:
                raise ValueError("managed directory workers do not accept pasted bearer tokens")
        elif self.worker_name == "generation":
            _require_managed_provider_url("AI base URL", self.ai_base_url)
            _require_managed_provider_url("training base URL", self.training_base_url)
            if not self.ai_model_id:
                raise ValueError("AI model ID is required: generation must pin the bake-off-selected model identity")
        elif self.worker_name == "mailbox":
            _require_managed_provider_url("reported mailbox URL", self.reported_mailbox_url)
            if self.reported_mailbox_provider != "microsoft365":
                raise ValueError("managed mailbox workers must use the microsoft365 provider")
            if _provider_hostname(self.reported_mailbox_url) != _MICROSOFT_GRAPH_HOST:
                raise ValueError("managed Microsoft 365 mailbox must use the native Microsoft Graph endpoint")
            _require_uuid("Microsoft tenant ID", self.microsoft_tenant_id)
            _require_uuid("reported mailbox client ID", self.reported_mailbox_client_id)
            if not self.reported_mailbox_id or _MAILBOX.fullmatch(self.reported_mailbox_id.strip()) is None:
                raise ValueError("reported mailbox ID must be a mailbox address")
            if not self.reported_mailbox_folder_id.strip() or len(self.reported_mailbox_folder_id) > 256:
                raise ValueError("reported mailbox folder ID is malformed")
            if self.reported_mailbox_bearer_token or any(
                (self.reported_mailbox_basic_username, self.reported_mailbox_basic_password)
            ):
                raise ValueError("managed Microsoft 365 mailbox must use its dedicated managed identity")
        elif self.worker_name == "retention":
            try:
                self.require_awareness_pseudonym_config()
            except RuntimeError as exc:
                raise ValueError(str(exc)) from None

        if self.worker_name in {"delivery", "reminder"}:
            _require_managed_provider_url("tracking base URL", self.tracking_base_url)
        if self.worker_name == "delivery":
            _require_managed_provider_url("training base URL", self.training_base_url)

        if self.worker_name in {"delivery", "reminder"}:
            if self.worker_name == "reminder":
                _require_managed_provider_url("training base URL", self.training_base_url)
                try:
                    self.require_training_token_hmac_key()
                except RuntimeError:
                    if not self.training_token_hmac_key:
                        raise ValueError(
                            "KP_WORKER_TRAINING_TOKEN_HMAC_KEY is required for training reminders"
                        ) from None
                    raise ValueError("KP_WORKER_TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
            if not self.smtp_sender:
                raise ValueError("SMTP sender is required for email workers in managed and production runtime modes")
            if self.email_provider_kind.is_acs:
                _require_acs_production_endpoint(self.acs_email_endpoint)
                _require_uuid("ACS sending managed identity client ID", self.acs_client_id)
                self.require_acs_delivery_ready()
                if self.worker_name == "delivery":
                    try:
                        self.require_acs_receipt_signing_key()
                    except RuntimeError:
                        raise ValueError(
                            "KP_WORKER_ACS_RECEIPT_SIGNING_KEY must be configured as a 256-bit hex key"
                        ) from None
            else:
                if not self.smtp_address:
                    raise ValueError(
                        "SMTP address is required for email workers in managed and production runtime modes"
                    )
                hostname = _smtp_hostname(self.smtp_address)
                if hostname is None:
                    raise ValueError("SMTP address must use host:port format")
                if _is_local_provider_host(hostname):
                    raise ValueError("SMTP address must use a non-local host in managed and production runtime modes")
                if not self.smtp_ssl and not self.effective_smtp_starttls:
                    raise ValueError("SMTP must use SSL or STARTTLS in managed and production runtime modes")

    def _validate_audit_anchor_container_url(self) -> str:
        value = (self.audit_anchor_container_url or "").strip()
        try:
            parsed = urlparse(value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError:
            raise ValueError("audit anchor container URL must identify one Azure Blob container over HTTPS") from None
        path_parts = [part for part in parsed.path.split("/") if part]
        if (
            parsed.scheme != "https"
            or hostname is None
            or not hostname.lower().endswith(".blob.core.windows.net")
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(path_parts) != 1
        ):
            raise ValueError("audit anchor container URL must identify one Azure Blob container over HTTPS")
        return value.rstrip("/")

    def require_audit_anchor_configured(self) -> tuple[str, str]:
        container_url = self._validate_audit_anchor_container_url()
        client_id = self.audit_anchor_client_id
        try:
            _require_uuid("audit anchor managed identity client ID", client_id)
        except ValueError:
            raise ValueError("audit anchor managed identity client ID must be a complete UUID") from None
        if client_id is None:
            raise ValueError("audit anchor managed identity client ID must be a complete UUID")
        return container_url, client_id.strip()

    def recipient_domain_allowlist(self) -> frozenset[str]:
        return parse_domain_allowlist(self.allowed_recipient_domains)

    def graph_group_id_set(self) -> tuple[str, ...]:
        """Normalized, unique Entra groups selected for recipient synchronization."""
        group_ids = tuple(
            dict.fromkeys(item.strip().lower() for item in self.graph_group_ids.split(",") if item.strip())
        )
        if any(_UUID.fullmatch(group_id) is None for group_id in group_ids):
            raise ValueError("Graph directory group IDs must be comma-separated UUIDs")
        return group_ids

    def sending_domain_pool(self) -> frozenset[str]:
        return parse_domain_allowlist(self.sending_domains)

    def brand_allowlist_set(self) -> set[str]:
        return {d.strip().lower() for d in self.brand_allowlist.split(",") if d.strip()}

    @property
    def email_provider_kind(self) -> EmailProviderKind:
        """Resolved transport kind; never branch on the raw string."""

        return EmailProviderKind(self.email_provider)

    @property
    def effective_smtp_address(self) -> str:
        return self.smtp_address or self.mailpit_smtp

    @property
    def effective_smtp_sender(self) -> str:
        if self.runtime_mode in _MANAGED_RUNTIME_MODES and self.email_provider_kind.is_acs:
            # Re-check time-bounded evidence whenever a delivery/reminder asks
            # for its sender, not only when the long-running worker starts.
            self.require_acs_delivery_ready()
        return self.smtp_sender or self.reminder_sender

    def require_acs_delivery_ready(self, *, now: datetime | None = None) -> None:
        """Fail closed unless managed ACS customer-domain evidence is current."""
        if self.acs_email_connection_string:
            raise ValueError("managed ACS delivery must use managed identity, not a connection string")
        domain = (self.acs_sending_domain or "").strip().lower().rstrip(".")
        local_part = (self.acs_sender_local_part or "").strip().lower()
        sender = (self.smtp_sender or "").strip().lower()
        if not _ACS_DOMAIN.fullmatch(domain) or domain == "azurecomm.net" or domain.endswith(".azurecomm.net"):
            raise ValueError("ACS sending domain must be a customer-managed public DNS domain")
        if not _ACS_LOCAL_PART.fullmatch(local_part):
            raise ValueError("ACS sender local part is malformed")
        if sender != f"{local_part}@{domain}":
            raise ValueError("ACS sender mailbox must match the configured local part and sending domain")
        display = self.acs_sender_display_name.strip()
        if not display or len(display) > 64 or any(ord(character) < 32 for character in display):
            raise ValueError("ACS sender display name must be 1-64 printable characters")
        statuses = (
            self.acs_domain_verification_status,
            self.acs_spf_verification_status,
            self.acs_dkim_verification_status,
            self.acs_dkim2_verification_status,
            self.acs_sender_username_status,
        )
        if any(status.strip().lower() != "verified" for status in statuses):
            raise ValueError("ACS domain, SPF, DKIM, DKIM2, and sender username must all be verified")
        if not self.acs_readiness_checked_at:
            raise ValueError("ACS readiness evidence timestamp is required")
        try:
            checked_at = datetime.fromisoformat(self.acs_readiness_checked_at.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("ACS readiness evidence timestamp must be RFC 3339") from None
        if checked_at.tzinfo is None:
            raise ValueError("ACS readiness evidence timestamp must include a timezone")
        current = now or datetime.now(UTC)
        checked_at = checked_at.astimezone(UTC)
        if checked_at > current + timedelta(minutes=5) or current - checked_at > timedelta(
            hours=self.acs_readiness_max_age_hours
        ):
            raise ValueError("ACS readiness evidence is stale or future-dated")
        daily_limit = self.acs_daily_message_limit
        per_minute = self.acs_messages_per_minute
        ramp_batch = self.acs_ramp_batch_size
        ramp_interval = self.acs_ramp_interval_seconds
        if daily_limit is None or per_minute is None or ramp_batch is None or ramp_interval is None:
            raise ValueError("ACS quota and ramp pacing inputs are required")
        if per_minute > daily_limit:
            raise ValueError("ACS per-minute limit cannot exceed the daily limit")
        if ramp_batch > per_minute:
            raise ValueError("ACS ramp batch cannot exceed the per-minute limit")

    def require_acs_receipt_signing_key(self) -> bytes:
        """Return the ingress-to-worker receipt integrity key."""
        try:
            key = bytes.fromhex(self.acs_receipt_signing_key)
        except ValueError:
            raise RuntimeError("KP_WORKER_ACS_RECEIPT_SIGNING_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("KP_WORKER_ACS_RECEIPT_SIGNING_KEY must be a 256-bit hex key")
        return key

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
        except ValueError:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY must be a hex string") from None
        if len(key) != 32:
            raise RuntimeError("KP_WORKER_AUDIT_HMAC_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_roe_signing_key(self) -> bytes:
        if not self.roe_signing_key:
            raise RuntimeError("KP_ROE_SIGNING_KEY is required to verify Rules-of-Engagement")
        try:
            key = bytes.fromhex(self.roe_signing_key)
        except ValueError:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a hex string") from None
        if len(key) != 32:
            raise RuntimeError("KP_ROE_SIGNING_KEY must be a 256-bit hex key (64 hex chars)")
        return key

    def require_kek(self) -> bytes:
        if not self.ciphertext_kek:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK is required")
        if re.fullmatch(r"[0-9a-fA-F]{64}", self.ciphertext_kek) is None:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEK must be a 256-bit hex key (64 hex chars)") from None
        return bytes.fromhex(self.ciphertext_kek)

    def require_cipher_keyring(self) -> tuple[str, bytes, dict[str, bytes]]:
        """Return the active write key and bounded prior decrypt-only keys."""
        active_key = self.require_kek()
        active_key_id = self.ciphertext_key_id.strip()
        if _CIPHERTEXT_KEY_ID.fullmatch(active_key_id) is None:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_KEY_ID must contain 1-32 ASCII letters, digits, '_' or '-'")

        raw_entries = self.ciphertext_prior_keys.split(",") if self.ciphertext_prior_keys.strip() else []
        if len(raw_entries) > _MAX_CIPHERTEXT_PRIOR_KEYS:
            raise RuntimeError("KP_WORKER_CIPHERTEXT_PRIOR_KEYS supports at most four entries")
        prior_keys: dict[str, bytes] = {}
        for entry in raw_entries:
            key_id, separator, key_hex = entry.strip().partition("=")
            if not separator or _CIPHERTEXT_KEY_ID.fullmatch(key_id) is None:
                raise RuntimeError("KP_WORKER_CIPHERTEXT_PRIOR_KEYS must use comma-separated key-id=64-hex entries")
            if key_id == active_key_id or key_id in prior_keys:
                raise RuntimeError("KP_WORKER_CIPHERTEXT_PRIOR_KEYS key identifiers must be unique")
            if re.fullmatch(r"[0-9a-fA-F]{64}", key_hex) is None:
                raise RuntimeError("KP_WORKER_CIPHERTEXT_PRIOR_KEYS key material must be 256-bit hexadecimal") from None
            key = bytes.fromhex(key_hex)
            if key == active_key or key in prior_keys.values():
                raise RuntimeError("KP_WORKER_CIPHERTEXT_PRIOR_KEYS must not reuse key material")
            prior_keys[key_id] = key
        return active_key_id, active_key, prior_keys

    def require_awareness_pseudonym_config(self) -> tuple[bytes, str]:
        """Return the stable key and governed version used only by retention.

        Development has one deterministic synthetic value so disposable local
        databases remain reproducible. Managed modes never fall back to it.
        """

        key_hex = self.awareness_pseudonym_key
        version = self.awareness_pseudonym_key_version
        if self.runtime_mode == "development":
            key_hex = key_hex or LOCAL_AWARENESS_PSEUDONYM_KEY
            version = version or LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION
        if re.fullmatch(r"[0-9a-f]{64,128}", key_hex) is None or len(key_hex) % 2 != 0:
            raise RuntimeError(
                "KP_WORKER_AWARENESS_PSEUDONYM_KEY must be a 32-64-byte lowercase hexadecimal key"
            ) from None
        if _AWARENESS_PSEUDONYM_KEY_VERSION.fullmatch(version) is None:
            raise RuntimeError(
                "KP_WORKER_AWARENESS_PSEUDONYM_KEY_VERSION must be a governed 1-32 character identifier"
            ) from None
        return bytes.fromhex(key_hex), version

    def require_recipient_hash_salt(self) -> bytes:
        if not self.recipient_hash_salt:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT is required")
        try:
            salt = bytes.fromhex(self.recipient_hash_salt)
        except ValueError:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT must be a hex string") from None
        if len(salt) < 16:
            raise RuntimeError("KP_WORKER_RECIPIENT_HASH_SALT must be at least 16 bytes")
        return salt

    def training_domain_set(self) -> set[str]:
        return {d.strip().lower() for d in self.training_domains.split(",") if d.strip()}

    def require_training_token_hmac_key(self) -> bytes:
        if not self.training_token_hmac_key:
            raise RuntimeError("KP_WORKER_TRAINING_TOKEN_HMAC_KEY is required for training reminders")
        try:
            key = bytes.fromhex(self.training_token_hmac_key)
        except ValueError:
            raise RuntimeError("KP_WORKER_TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("KP_WORKER_TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key")
        return key

    def alert_webhook_domain_set(self) -> set[str]:
        return {d.strip().lower() for d in self.alert_webhook_domains.split(",") if d.strip()}
