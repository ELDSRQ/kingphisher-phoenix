"""Calendar-invite (ICS) lure generation.

Ported from the original King Phisher `king_phisher/ics.py`. Produces a
minimal, standards-shaped VCALENDAR/VEVENT attachment. In Phoenix this is a
training lure only. When delivery supplies its recipient-bound tracked URL,
the event exposes that URL in both its description and URL property so a
"clicked" is attributed through the normal tracking pipeline.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

_ICS_FMT = "%Y%m%dT%H%M%SZ"


def _escape(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def generate_invite(
    *,
    organizer_email: str,
    attendee_email: str,
    event_title: str,
    description: str,
    recipient_bound_tracked_url: str | None = None,
    starts_at: datetime | None = None,
    duration_minutes: int = 30,
) -> tuple[str, str]:
    """Return `(ics_text, uid)` for a calendar-invite training lure.

    The optional URL is supplied only after delivery creates the recipient's
    existing click bearer; this function never creates a token or destination.
    """
    starts_at = starts_at or (datetime.now(UTC) + timedelta(days=7))
    ends_at = starts_at + timedelta(minutes=duration_minutes)
    uid = hashlib.sha256(f"{attendee_email}|{event_title}|{starts_at.isoformat()}".encode()).hexdigest()[:32]
    dtstamp = datetime.now(UTC).strftime(_ICS_FMT)
    event_description = description
    if recipient_bound_tracked_url:
        event_description = (
            f"{description}\nOpen the tracked security-awareness exercise: {recipient_bound_tracked_url}"
        )
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
        f"DESCRIPTION:{_escape(event_description)}",
        *([f"URL:{_escape(recipient_bound_tracked_url)}"] if recipient_bound_tracked_url else []),
        f"ORGANIZER;CN={_escape('Security Awareness')}:mailto:{organizer_email}",
        f"ATTENDEE;CN={_escape(attendee_email)};ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:{attendee_email}",
        "SEQUENCE:0",
        "STATUS:CONFIRMED",
        "TRANSP:OPAQUE",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n", uid
