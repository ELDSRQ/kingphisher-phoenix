from __future__ import annotations

import ipaddress
from typing import Literal

from kp_telemetry.settings import local_dotenv_file
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MAX_TRUSTED_PROXY_NETWORKS = 16
_MAX_TRUSTED_PROXY_ADDRESSES = 4096


def _trusted_proxy_networks(value: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a bounded, canonical set of trusted ingress networks."""

    if not value.strip():
        return ()
    raw_networks = [part.strip() for part in value.split(",")]
    if any(not part for part in raw_networks) or len(raw_networks) > _MAX_TRUSTED_PROXY_NETWORKS:
        raise ValueError("TRACKING_API_TRUSTED_PROXIES must contain 1-16 non-empty IP networks")

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_network in raw_networks:
        try:
            network = ipaddress.ip_network(raw_network, strict=True)
        except ValueError:
            raise ValueError("TRACKING_API_TRUSTED_PROXIES contains an invalid or non-canonical IP network") from None
        if (
            network.num_addresses > _MAX_TRUSTED_PROXY_ADDRESSES
            or network.network_address.is_multicast
            or network.network_address.is_unspecified
        ):
            raise ValueError("TRACKING_API_TRUSTED_PROXIES contains an unsafe IP network")
        if any(network.overlaps(existing) for existing in networks):
            raise ValueError("TRACKING_API_TRUSTED_PROXIES contains duplicate or overlapping IP networks")
        networks.append(network)
    return tuple(networks)


class TrackingApiSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TRACKING_API_",
        env_file=local_dotenv_file(),
        extra="ignore",
        populate_by_name=True,
        hide_input_in_errors=True,
    )

    app_name: str = "kp-tracking-api"
    host: str = "127.0.0.1"
    port: int = 8001
    database_url: str = "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher"
    training_base_url: str = "http://127.0.0.1:8001/v1/training/awareness"
    rate_limit_ip_per_min: int = 60
    rate_limit_token_per_min: int = 5
    rate_limit_global_per_min: int = 3000
    rate_limit_max_keys: int = 10_000
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    redis_url: str = ""
    # HIGH-09 residual: request-body cap for this API (64 KiB default).
    max_body_bytes: int = 65_536
    tracking_token_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices("TRACKING_API_TRACKING_TOKEN_HMAC_KEY", "TRACKING_TOKEN_HMAC_KEY"),
    )
    training_token_hmac_key: str = Field(
        default="",
        validation_alias=AliasChoices("TRACKING_API_TRAINING_TOKEN_HMAC_KEY", "TRAINING_TOKEN_HMAC_KEY"),
    )
    trusted_proxies: str = ""
    log_level: str = "info"

    @model_validator(mode="after")
    def validate_rate_limit_backend(self) -> TrackingApiSettings:
        if self.rate_limit_backend == "redis" and not self.redis_url.strip():
            raise ValueError("TRACKING_API_REDIS_URL is required when rate limiting uses Redis")
        networks = _trusted_proxy_networks(self.trusted_proxies)
        self.trusted_proxies = ",".join(str(network) for network in networks)
        return self

    def is_trusted_proxy(self, address: str) -> bool:
        """Return whether an exact peer address belongs to a reviewed ingress network."""

        try:
            peer = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError:
            return False
        return any(peer in network for network in _trusted_proxy_networks(self.trusted_proxies))

    def require_tracking_token_hmac_key(self) -> bytes:
        if not self.tracking_token_hmac_key:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY is required to verify tracking bearers")
        try:
            key = bytes.fromhex(self.tracking_token_hmac_key)
        except ValueError:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("TRACKING_TOKEN_HMAC_KEY must be a 256-bit hex key")
        return key

    def require_training_token_hmac_key(self) -> bytes:
        if not self.training_token_hmac_key:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY is required to verify training bearers")
        try:
            key = bytes.fromhex(self.training_token_hmac_key)
        except ValueError:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key") from None
        if len(key) != 32:
            raise RuntimeError("TRAINING_TOKEN_HMAC_KEY must be a 256-bit hex key")
        return key
