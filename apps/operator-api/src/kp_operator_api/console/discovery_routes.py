"""P3 discovery consumer: on-demand web-search threat leads for operator review.

The console triggers the gateway's POST /discover (the single place the
platform reaches the public web) and returns the cited, allow-listed leads for
human review. Nothing auto-promotes a lead: the operator promotes it through
the existing threat-activation path (MANAGE_SOURCES).

The gateway requires its own shared bearer secret (KP_AI_GATEWAY_API_KEY),
which is provisioned from Key Vault in Azure and from .env locally — never a
caller-supplied value. When the gateway URL is unset (on-prem/disconnected), the
route returns 503 rather than attempting any egress.
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.discovery import (
    DEFAULT_ALLOWED_CITATION_DOMAINS,
    MAX_DISCOVERY_QUERY_CHARS,
    assert_pii_free_query,
)
from pydantic import BaseModel, Field

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_settings

router = APIRouter(prefix="/api/v1/console/discover", tags=["console", "discovery"])

_GATEWAY_TIMEOUT_SECONDS = 60.0


class DiscoverRequest(BaseModel):
    """Operator-submitted query for web-search threat discovery (public terms only)."""

    query: str = Field(min_length=1, max_length=MAX_DISCOVERY_QUERY_CHARS)


@router.post("/search", status_code=status.HTTP_200_OK)
async def discover_search(
    body: DiscoverRequest,
    request: Request,
    settings: OperatorApiSettings = Depends(get_settings),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """Run a web-search discovery and return cited, allow-listed leads.

    Performs the PII-free-query backstop locally (fail closed before any egress)
    and forwards Authorization to the gateway using the *shared* gateway bearer
    secret, never the caller's token.
    """
    gateway_url = settings.ai_gateway_url.strip()
    if not gateway_url:
        raise HTTPException(status_code=503, detail="discovery is not configured")

    try:
        query = assert_pii_free_query(body.query)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="query must contain only public threat terms (no emails or PII)",
        ) from None

    headers = {"Content-Type": "application/json"}
    if settings.ai_gateway_api_key:
        headers["Authorization"] = f"Bearer {settings.ai_gateway_api_key}"

    endpoint = gateway_url.rstrip("/") + "/discover"
    try:
        async with httpx.AsyncClient(timeout=_GATEWAY_TIMEOUT_SECONDS) as client:
            response = await client.post(endpoint, json={"query": query}, headers=headers)
        if response.status_code == 503:
            raise HTTPException(status_code=503, detail="discovery is not configured on the gateway") from None
        if response.status_code == 422:
            raise HTTPException(status_code=422, detail="query rejected by the gateway") from None
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="discovery backend unavailable") from None
        data = response.json()
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="failed to reach the AI gateway") from None
    except ValueError:
        raise HTTPException(status_code=502, detail="discovery returned an invalid response") from None

    return {"leads": data.get("leads", []), "model_id": data.get("model_id", "")}


@router.get("/allowed-domains", status_code=status.HTTP_200_OK)
async def discover_allowed_domains(
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> list[str]:
    """Return the citation domains a lead must cite to survive the no-source gate."""
    return sorted(DEFAULT_ALLOWED_CITATION_DOMAINS)
