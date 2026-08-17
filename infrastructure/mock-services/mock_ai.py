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


class ProposeRequest(BaseModel):
    pattern_id: str


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
    "oidc": (
        "OIDC is the sign-in standard that lets your identity provider authenticate operators. "
        "Register this application, then copy its issuer, client ID, and redirect URL into setup.",
        {"next_field": "issuer URL", "safe_example": "https://login.example.com/tenant/v2.0"},
    ),
    "graph": (
        "The directory connection imports employee names and work addresses from a Graph-compatible API. "
        "Confirm the base URL and grant the application read-only user access.",
        {"next_field": "directory base URL", "permission": "read-only users"},
    ),
    "smtp": (
        "SMTP delivers simulations and reminders. Use your mail relay host, port, sender address, "
        "and the encryption mode required by your mail team.",
        {"typical_port": "587", "encryption": "STARTTLS"},
    ),
    "mailbox": (
        "The reported-message mailbox lets employees submit suspicious messages for analysis. "
        "Use a dedicated mailbox API URL and a read-only service identity.",
        {"access": "read-only mailbox", "purpose": "reported messages"},
    ),
    "ai": (
        "The AI connection proposes training content; deterministic safety checks still approve every result. "
        "Enter the provider endpoint and model name, then test before saving.",
        {"next_field": "provider endpoint", "control": "deterministic validation"},
    ),
    "training": (
        "The training URL is where learners go after a simulation. Use an approved HTTPS course URL "
        "and verify that completion callbacks reach this application.",
        {"next_field": "HTTPS course URL", "verify": "completion callback"},
    ),
    "webhook": (
        "Webhooks send signed campaign events to an approved HTTPS destination. Allowlist its hostname "
        "and verify signatures in the receiving system.",
        {"transport": "HTTPS", "verification": "HMAC signature"},
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
            {"next_step": "review documentation", "verification": "test connection"},
        ),
    )
    return {"answer": answer, "suggestions": suggestions}


@app.post("/propose")
async def propose(body: ProposeRequest, request: Request) -> dict[str, str]:
    seed = body.pattern_id + hashlib.sha256(await request.body()).hexdigest()[:8]
    return {
        "subject": f"Awareness scenario {seed[:6]}",
        "plain_text": (
            "This is a simulated awareness scenario for training only. "
            f"Review the scenario and complete the training module: {TRAINING_URL}"
        ),
        "safe_html": (
            "<p>This is a simulated awareness scenario for training only.</p>"
            f'<p><a href="{TRAINING_URL}">Complete the training module</a></p>'
        ),
        "model_id": "mock-ai/0.1.0",
    }
