"""Mock content-generation AI for local development.

Answers `POST /propose` with a deterministic, safety-passing template proposal
so the generation worker's full path (call AI -> deterministic validation ->
persist template) can be exercised without a real model. The response is
deliberately minimal and static; the SafetyValidator runs on the result just as
it would on a real model's output.
"""

from __future__ import annotations

import hashlib

from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI(title="mock-ai")

TRAINING_URL = "https://training.local/awareness/invoice-reference"


class ProposeRequest(BaseModel):
    pattern_id: str


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
