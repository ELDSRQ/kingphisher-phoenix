import pytest
from kp_templating.render import (
    CampaignContext,
    MessageRenderer,
    RecipientContext,
    TemplateVariableError,
    TrackingContext,
)


def test_render_whitelisted_variables() -> None:
    renderer = MessageRenderer()
    out = renderer.render(
        "Hi {{ recipient.first_name }}, {{ campaign.title }} open {{ tracking.open_url }} from {{ sender.email }}",
        recipient=RecipientContext(first_name="Ada"),
        campaign=CampaignContext(title="Phish"),
        tracking=TrackingContext(open_url="http://track/open/h"),
        sender_email="ops@example.com",
    )
    assert "Hi Ada, Phish" in out
    assert "http://track/open/h" in out
    assert "ops@example.com" in out


def test_render_rejects_unauthorized_variable() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ recipient.ssn }}",
            recipient=RecipientContext(first_name="Ada"),
            campaign=CampaignContext(title="Phish"),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_render_rejects_unknown_namespace() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ secrets.token }}",
            recipient=RecipientContext(),
            campaign=CampaignContext(),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_render_rejects_unknown_field() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ recipient.missing }}",
            recipient=RecipientContext(),
            campaign=CampaignContext(),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_html_render_escapes_untrusted_context_values() -> None:
    renderer = MessageRenderer()
    out = renderer.render(
        "<p>{{ recipient.first_name }} — {{ campaign.title }}</p>",
        recipient=RecipientContext(first_name='</p><img src="https://attacker.example/p">'),
        campaign=CampaignContext(title="<script>alert(1)</script>"),
        tracking=TrackingContext(),
        sender_email="ops@example.com",
        html_context=True,
    )
    assert "<img" not in out
    assert "<script>" not in out
    assert "&lt;img" in out
