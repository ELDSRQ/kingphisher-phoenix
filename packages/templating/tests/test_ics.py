from kp_templating.ics import generate_invite


def test_generate_invite_shape() -> None:
    text, uid = generate_invite(
        organizer_email="security@example.com",
        attendee_email="ada@example.com",
        event_title="Security awareness session",
        description="Recognized a simulation?",
    )
    assert text.startswith("BEGIN:VCALENDAR")
    assert "BEGIN:VEVENT" in text
    assert "END:VEVENT" in text
    assert "END:VCALENDAR" in text
    assert f"UID:{uid}" in text
    assert "mailto:ada@example.com" in text
    assert uid.isalnum() and len(uid) == 32
    assert "URL:" not in text
    assert "tracked security-awareness exercise" not in text


def test_generate_invite_exposes_only_supplied_recipient_bound_tracking_url() -> None:
    tracked_url = "https://tracking.example/v1/track/click/recipient-bearer"

    text, _ = generate_invite(
        organizer_email="security@example.com",
        attendee_email="ada@example.com",
        event_title="Security awareness session",
        description="Recognized a simulation?",
        recipient_bound_tracked_url=tracked_url,
    )

    assert f"URL:{tracked_url}\r\n" in text
    assert f"Open the tracked security-awareness exercise: {tracked_url}" in text
    assert text.count(tracked_url) == 2


def test_generate_invite_escapes_property_line_breaks() -> None:
    text, _ = generate_invite(
        organizer_email="security@example.com",
        attendee_email="ada@example.com",
        event_title="Security awareness\r\nATTACH:https://attacker.invalid/payload",
        description="Recognized a simulation?",
    )

    assert "\r\nATTACH:" not in text
    assert "SUMMARY:Security awareness\\nATTACH:https://attacker.invalid/payload" in text
