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
