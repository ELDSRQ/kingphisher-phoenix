"""Deployment handoffs must point to private credential retrieval."""

from __future__ import annotations

import re
from pathlib import Path


def test_session_handoffs_do_not_publish_console_password_literals() -> None:
    root = Path(__file__).resolve().parents[1]
    literal = re.compile(r"\b(?:password|pw)\s+`([^`]+)`", re.IGNORECASE)
    references = {"KP_CONSOLE_PASSWORD", ".env", "<console-password>", "<password>"}
    locations = []
    for path in sorted((root / "docs").glob("SESSION-HANDOFF-*.md")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(match.group(1) not in references for match in literal.finditer(line)):
                locations.append(f"{path.relative_to(root)}:{number}")
    # Report locations only: a failing guard must not print the credential.
    assert locations == [], "Retrieve console credentials privately; literals found at " + ", ".join(locations)
