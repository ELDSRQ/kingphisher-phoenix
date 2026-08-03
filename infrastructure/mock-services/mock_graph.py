"""Mock Azure Graph directory for local development.

The delivery worker's eventual directory-sync path reads recipients from a
Graph-style endpoint. This mock returns a small fixed roster (including two
`@example.com` test accounts) so local campaign delivery exercises the real
`Recipient` creation + encryption path. No real directory data is exposed.
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI

app = FastAPI(title="mock-graph")

ROSTER = [
    {"mail": "alex.rivera@example.com", "displayName": "Alex Rivera", "department": "Engineering"},
    {"mail": "jordan.lee@example.com", "displayName": "Jordan Lee", "department": "Finance"},
    {"mail": "sam.chen@example.com", "displayName": "Sam Chen", "department": "HR"},
    {"mail": "test+batch1@example.com", "displayName": "Batch Test 1", "department": "QA"},
    {"mail": "test+batch2@example.com", "displayName": "Batch Test 2", "department": "QA"},
]


@app.get("/users")
def users() -> dict[str, object]:
    rows = []
    for person in ROSTER:
        rows.append(
            {
                "id": str(uuid.uuid5(uuid.NAMESPACE_URL, person["mail"])),
                "mail": person["mail"],
                "displayName": person["displayName"],
                "department": person["department"],
            }
        )
    return {"value": rows, "@odata.count": len(rows)}
