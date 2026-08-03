"""Calendar-invite (ICS) lure generation.

Ported from the original King Phisher `king_phisher/ics.py`. Produces a
minimal, standards-shaped VCALENDAR/VEVENT attachment. In Phoenix this is a
training lure only: the event is titled as a security awareness session and
carries the per-recipient click URL so a "clicked" is still attributed via the
normal tracking pipeline.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

_ICS_FMT = "%Y%m%dT%H%M%SZ"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def generate_invite(
    *,
    organizer_email: str,
    attendee_email: str,
    event_title: str,
    description: str,
    starts_at: datetime | None = None,
    duration_minutes: int = 30,
) -> tuple[str, str]:
    """Return `(ics_text, uid)` for a calendar-invite training lure."""
    starts_at = starts_at or (datetime.now(UTC) + timedelta(days=7))
    ends_at = starts_at + timedelta(minutes=duration_minutes)
    uid = hashlib.sha256(f"{attendee_email}|{event_title}|{starts_at.isoformat()}".encode()).hexdigest()[:32]
    dtstamp = datetime.now(UTC).strftime(_ICS_FMT)
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Kingphisher-Phoenix//Training Lure//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:REQUEST",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{dtstamp}",
        f"DTSTART:{starts_at.astimezone(UTC).strftime(_ICS_FMT)}",
        f"DTEND:{ends_at.astimezone(UTC).strftime(_ICS_FMT)}",
        f"SUMMARY:{_escape(event_title)}",
        f"DESCRIPTION:{_escape(description)}",
        f"ORGANIZER;CN={_escape('Security Awareness')}:mailto:{organizer_email}",
        f"ATTENDEE;CN={_escape(attendee_email)};ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:{attendee_email}",
        "SEQUENCE:0",
        "STATUS:CONFIRMED",
        "TRANSP:OPAQUE",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n", uid
