"""Bounded JSON transport for identity-provider responses."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

MAX_OIDC_DISCOVERY_BYTES = 64 * 1024
MAX_OIDC_TOKEN_RESPONSE_BYTES = 64 * 1024
MAX_OIDC_JWKS_BYTES = 256 * 1024


class OidcProviderResponseError(ValueError):
    """Stable, content-free failure at an OIDC provider boundary."""


def _validate_content_length(response: httpx.Response, *, max_bytes: int) -> None:
    values = response.headers.get_list("content-length")
    if len(values) > 1:
        raise OidcProviderResponseError("identity provider returned duplicate Content-Length headers")
    if not values:
        return
    declared = values[0]
    if len(declared) > 19 or re.fullmatch(r"[0-9]+", declared) is None:
        raise OidcProviderResponseError("identity provider returned a malformed Content-Length header")
    if int(declared) > max_bytes:
        raise OidcProviderResponseError("identity provider response exceeds the maximum size")


def _parse_json(body: bytearray) -> Any:
    try:
        return json.loads(bytes(body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise OidcProviderResponseError("identity provider response is not valid JSON") from None


def bounded_json(response: httpx.Response, *, max_bytes: int) -> Any:
    """Read a sync response with declared and decoded-byte limits."""

    _validate_content_length(response, max_bytes=max_bytes)
    body = bytearray()
    for chunk in response.iter_bytes():
        # iter_bytes() is decoded by httpx, so compressed expansion is bounded
        # independently of the provider's encoded Content-Length.
        if len(body) + len(chunk) > max_bytes:
            raise OidcProviderResponseError("identity provider response exceeds the maximum size")
        body.extend(chunk)
    return _parse_json(body)


async def bounded_json_async(response: httpx.Response, *, max_bytes: int) -> Any:
    """Read an async response with declared and decoded-byte limits."""

    _validate_content_length(response, max_bytes=max_bytes)
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise OidcProviderResponseError("identity provider response exceeds the maximum size")
        body.extend(chunk)
    return _parse_json(body)
