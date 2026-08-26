"""Mock content-generation AI for local development.

Answers `POST /propose` with a deterministic, safety-passing template proposal
so the generation worker's full path (call AI -> deterministic validation ->
persist template) can be exercised without a real model. The response is
deliberately minimal and static; the SafetyValidator runs on the result just as
it would on a real model's output.
"""

from __future__ import annotations

import hashlib
import re
from typing import Self

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

app = FastAPI(title="mock-ai")

TRAINING_URL = "https://training.local/awareness/invoice-reference"


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
    """Avoid reflecting rejected setup secrets through Pydantic's input diagnostics."""

    return JSONResponse(status_code=422, content={"detail": "request validation failed"})


class ProposePatternContext(BaseModel):
    """Mirrors kp_contracts.generation.PatternContext.

    Kept permissive on unknown keys so a contract addition does not break the
    offline stack, but the fields the mock actually uses are declared.
    """

    pattern_id: str
    lure_category: str = "unknown"
    impersonation_category: str = ""
    target_role_category: str = ""
    requested_action: str = ""
    emotional_triggers: list[str] = []
    attack_mapping: dict[str, object] = {}
    confidence: str = ""
    source_excerpts: list[str] = []


class ProposeRequest(BaseModel):
    """Accepts the enriched contract, and the bare legacy shape."""

    pattern_id: str | None = None
    pattern: ProposePatternContext | None = None
    as_of: str = ""
    context_untrusted: bool = False
    neutralization_reasons: list[str] = []
    training_url: str = ""
    guidance: str = ""

    @model_validator(mode="after")
    def require_a_pattern(self) -> Self:
        if self.pattern is None and not self.pattern_id:
            raise ValueError("either pattern or pattern_id is required")
        return self

    @property
    def effective_pattern_id(self) -> str:
        return self.pattern.pattern_id if self.pattern else str(self.pattern_id)


_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|credential|password|passwd|private[_-]?key|secret|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:api[_-]?key|client[_-]?secret|password|token)\s*[:=]\s*\S+|"
    r"\b(?:sk|xox[baprs]|gh[pousr])[-_][A-Za-z0-9_-]{8,}|"
    r"https?://[^\s/:]+:[^\s/@]+@)",
    re.IGNORECASE,
)


class SetupAssistRequest(BaseModel):
    """Bounded, deliberately non-secret context for local setup guidance."""

    model_config = ConfigDict(extra="forbid")

    component: str = Field(min_length=1, max_length=40)
    question: str = Field(min_length=1, max_length=500)
    values: dict[str, str] = Field(default_factory=dict)

    @field_validator("component", "question")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        value = value.strip()
        if _SECRET_VALUE.search(value):
            raise ValueError("setup assistance accepts non-secret context only")
        return value

    @model_validator(mode="after")
    def validate_values(self) -> Self:
        if len(self.values) > 12:
            raise ValueError("at most 12 non-secret values may be supplied")
        for key, value in self.values.items():
            if not key or len(key) > 40 or len(value) > 300:
                raise ValueError("setup value names and values exceed safe limits")
            if _SECRET_KEY.search(key) or _SECRET_VALUE.search(value):
                raise ValueError("setup assistance accepts non-secret context only")
        return self


_SETUP_GUIDANCE: dict[str, tuple[str, dict[str, str]]] = {
    "identity": (
        "OIDC is the sign-in standard that lets your identity provider authenticate operators. "
        "Register this application, then copy its issuer, client ID, and redirect URL into setup.",
        {"OPERATOR_API_OIDC_MODE": "oidc"},
    ),
    "graph": (
        "The directory connection imports employee names and work addresses from a Graph-compatible API. "
        "Confirm the base URL and grant the application read-only user access.",
        {"KP_WORKER_GRAPH_BASE_URL": "https://graph.microsoft.com/v1.0"},
    ),
    "smtp": (
        "SMTP delivers simulations and reminders. Use your mail relay host, port, sender address, "
        "and the encryption mode required by your mail team.",
        {"KP_WORKER_SMTP_STARTTLS": "true"},
    ),
    "mailbox": (
        "The reported-message mailbox lets employees submit suspicious messages for analysis. "
        "Use a dedicated mailbox API URL and a read-only service identity.",
        {},
    ),
    "ai": (
        "The AI connection proposes training content; deterministic safety checks still approve every result. "
        "Enter the provider endpoint and model name, then test before saving.",
        {},
    ),
    "training": (
        "The training URL is where learners go after a simulation. Use an approved HTTPS course URL "
        "and verify that completion callbacks reach this application.",
        {},
    ),
    "webhook": (
        "The allowed webhook domain is the hostname of an approved HTTPS application that receives signed "
        "operational alerts. It is not an email destination and does not require an MTA or mail relay. "
        "Allowlist the receiver's hostname and verify HMAC signatures in that application.",
        {},
    ),
}


@app.post("/setup-assist")
async def setup_assist(body: SetupAssistRequest) -> dict[str, object]:
    """Return deterministic guidance without transmitting or reflecting supplied values."""

    answer, suggestions = _SETUP_GUIDANCE.get(
        body.component.casefold(),
        (
            "Review the component documentation, enter only non-secret connection details here, "
            "and use the connection test before saving. Keep credentials in the designated secret fields.",
            {},
        ),
    )
    return {"answer": answer, "suggestions": suggestions}


#: Per-lure subject lines, so a reviewer sees content that actually reflects
#: the approved pattern rather than the same placeholder every time.
_LURE_SUBJECTS = {
    "invoice": "Outstanding invoice requires your review",
    "credential_harvest": "Action required: confirm your account details",
    "delivery_notice": "Your delivery could not be completed",
    "hr_policy": "Updated policy acknowledgement required",
    "it_support": "Scheduled maintenance: confirm your workstation",
    "calendar_invite": "Meeting invitation: quarterly security briefing",
}


@app.post("/propose")
async def propose(body: ProposeRequest, request: Request) -> dict[str, str]:
    """Deterministic, safety-passing proposal shaped by the supplied context.

    The response is intentionally limited to the four fields the generation
    contract declares: a gateway cannot return an approval, a recipient, or a
    schedule, and the platform re-validates and human-approves regardless.
    """
    pattern_id = body.effective_pattern_id
    seed = pattern_id + hashlib.sha256(await request.body()).hexdigest()[:8]
    lure = body.pattern.lure_category if body.pattern else "unknown"
    impersonated = (body.pattern.impersonation_category if body.pattern else "") or "your organisation"
    training_url = body.training_url or TRAINING_URL

    subject = _LURE_SUBJECTS.get(lure, f"Awareness scenario {seed[:6]}")
    lead = (
        f"This is a simulated awareness scenario for training only. It imitates a {lure.replace('_', ' ')} "
        f"message appearing to come from {impersonated}."
    )
    return {
        "subject": subject,
        "plain_text": f"{lead} Review the scenario and complete the training module: {training_url}",
        "safe_html": (f'<p>{lead}</p><p><a href="{training_url}">Complete the training module</a></p>'),
        "model_id": "mock-ai/0.2.0",
    }
